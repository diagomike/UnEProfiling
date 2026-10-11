"""Adapters: one per kind of log. Each turns files into the event table (events.py).

    cert      the CERT Insider Threat Test Dataset (logon, device, file, email, web + directory + answer key)
    windows   Windows Security events: .evtx files, JSON lines (Winlogbeat, Wazuh, Security-Datasets),
              or a CSV exported from Event Viewer / Get-WinEvent
    sshd      Linux auth logs (sshd and sudo lines)
    table     any CSV whose columns you name in the workspace config (VPN, proxy, badge, application logs)

An adapter is a class with `files(path)` (what there is to read, so a later run can skip what it
has already read) and `read(file)` (yields event tables). `directory(path)` and `labels(path)` are
optional: who is who, and known incidents to measure against.
"""
from __future__ import annotations

import csv
import glob
import json
import os
import re

import numpy as np
import pandas as pd

from .events import frame


def _domain(s: pd.Series) -> pd.Series:
    return s.str.extract(r"@([^;@\s]+)", expand=False).fillna("").str.lower()


class Cert:
    """CERT r4.x as fetched by fetch_data.py: logon.csv, device.csv, file.csv, and the reduced
    email/ and http/ Parquet parts. Whatever is missing is skipped."""
    name = "cert"

    def __init__(self, options=None):
        self.o = options or {}
        self.company = self.o.get("company_domain", "dtaa.com")

    def files(self, path):
        out = [os.path.join(path, f) for f in ("logon.csv", "device.csv", "file.csv") if os.path.exists(os.path.join(path, f))]
        for part in ("email", "http"):
            if os.path.exists(os.path.join(path, part, "_state.json")) and json.load(open(os.path.join(path, part, "_state.json"))).get("done"):
                out += sorted(glob.glob(os.path.join(path, part, "part-*.parquet")))
        return out

    def read(self, file):
        kind = os.path.basename(os.path.dirname(file)) if file.endswith(".parquet") else os.path.basename(file)[:-4]
        if kind in ("logon", "device", "file"):
            for d in pd.read_csv(file, usecols=lambda c: c != "content", chunksize=1_000_000):
                ts = pd.to_datetime(d["date"], format="%m/%d/%Y %H:%M:%S")
                if kind == "logon":
                    yield frame(id=d.id, ts=ts, actor=d.user, host=d.pc, action=d.activity.str.lower(), source="logon")
                elif kind == "device":
                    yield frame(id=d.id, ts=ts, actor=d.user, host=d.pc, source="usb",
                                action=np.where(d.activity == "Connect", "usb_connect", "usb_disconnect"))
                else:                                           # in r4.2 every file event is a copy to a removable drive
                    yield frame(id=d.id, ts=ts, actor=d.user, host=d.pc, action="file_to_usb", source="file",
                                object=d.filename.str.rsplit(".", n=1).str[-1].str.lower())
        elif kind == "email":
            d = pd.read_parquet(file)
            rcpt = (d["to"].fillna("") + ";" + d["cc"].fillna("") + ";" + d["bcc"].fillna("")).str.lower()
            # outside domains this message went to, e.g. "raytheon.com;gmail.com"
            doms = rcpt.str.findall(r"@([^;@\s]+)").map(lambda xs: ";".join(sorted({x for x in xs if x != self.company})))
            personal = _domain(d["from"].fillna("")).ne(self.company)
            yield frame(id=d.id, ts=d.date, actor=d.user.astype(str), host=d.pc.astype(str), action="email_send", source="email",
                        object=np.where(personal, "from-personal;", "") + doms, amount=d.attachments, external=doms.ne(""))
        elif kind == "http":
            d = pd.read_parquet(file)
            yield frame(id=d["id"] if "id" in d else "", ts=d.date, actor=d.user.astype(str), host=d.pc.astype(str) if "pc" in d else "",
                        action="web_visit", object=d.domain.astype(str), external=True, source="web")

    def directory(self, path):
        fs = sorted(glob.glob(os.path.join(path, "LDAP", "*.csv")))
        if not fs:
            return None
        ld = pd.concat([pd.read_csv(f).assign(month=os.path.basename(f)[:7]) for f in fs]).sort_values("month")
        last = ld.month.max()
        who = ld.groupby("user_id").agg(name=("employee_name", "first"), role=("role", "first"), department=("department", "first"),
                                        team=("team", "first"), manager=("supervisor", "first"), last_listed=("month", "last"))
        who.index.name = "actor"
        for c in ("department", "team"):
            who[c] = who[c].astype(str).str.replace(r"^\d+ - ", "", regex=True).replace("nan", "")
        who["left"] = np.where(who.last_listed < last, who.last_listed, "")      # no longer in the directory after this month
        return who.drop(columns="last_listed").reset_index()

    def labels(self, path):
        """The red-team answer key, if it sits beside the data: one row per scripted event. `incident` names
        the insider; `actor` is the account the event ran under, which in the impersonation scenario is
        sometimes the victim's."""
        root = os.path.join(os.path.dirname(os.path.abspath(path)), "answers")
        release = self.o.get("release", "4.2")
        rows = []
        for f in glob.glob(os.path.join(root, f"r{release}-*", "*.csv")):
            scenario = int(os.path.basename(os.path.dirname(f)).rsplit("-", 1)[1])
            who = os.path.basename(f)[:-4].rsplit("-", 1)[1]
            for line in open(f, encoding="utf-8", errors="ignore"):
                p = line.split(",", 4)
                if len(p) >= 4:
                    rows.append((p[1], p[2], p[3], scenario, {"device": "usb", "http": "web"}.get(p[0], p[0]), who))
        if not rows:
            return None
        d = pd.DataFrame(rows, columns=["id", "ts", "actor", "scenario", "source", "incident"])
        d["ts"] = pd.to_datetime(d.ts, format="%m/%d/%Y %H:%M:%S")
        return d


# Windows Security event id -> action. 4624 is split by logon type below.
_WIN = {4625: "logon_failed", 4771: "logon_failed", 4776: None, 4634: "logoff", 4647: "logoff", 4648: "explicit_cred",
        4672: "privileged", 1102: "log_cleared", 4720: "account_change", 4722: "account_change", 4724: "account_change",
        4726: "account_change", 4728: "account_change", 4732: "account_change", 4738: "account_change", 4740: "account_change",
        4756: "account_change", 6416: "usb_connect", 4688: "process", 4663: "file_to_usb"}
_SYSTEM = {"system", "local service", "network service", "anonymous logon", "-", "", "dwm-1", "umfd-0", "umfd-1"}


class Windows:
    """Windows Security log. Machine accounts (ending in $) and service identities are dropped:
    this is about people. Network logons (type 3) are dropped too unless options.network is true,
    because every file share and printer makes them."""
    name = "windows"

    def __init__(self, options=None):
        self.o = options or {}

    def files(self, path):
        if os.path.isfile(path):
            return [path]
        return sorted(f for f in glob.glob(os.path.join(path, "**", "*"), recursive=True) if f.lower().endswith((".evtx", ".json", ".jsonl", ".ndjson", ".csv")))

    def _records(self, file):
        low = file.lower()
        if low.endswith(".evtx"):
            import xml.etree.ElementTree as ET

            from Evtx.Evtx import Evtx                                   # pip install python-evtx
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            with Evtx(file) as log:
                for rec in log.records():
                    try:
                        x = ET.fromstring(rec.xml())
                    except Exception:
                        continue
                    s = x.find(ns + "System")
                    r = {"EventID": s.findtext(ns + "EventID"), "Computer": s.findtext(ns + "Computer"),
                         "TimeCreated": s.find(ns + "TimeCreated").get("SystemTime")}
                    for e in x.iter(ns + "Data"):
                        if e.get("Name"):
                            r[e.get("Name")] = e.text or ""
                    yield r
        elif low.endswith(".csv"):
            with open(file, encoding="utf-8-sig", errors="replace", newline="") as f:
                for r in csv.DictReader(f):
                    yield r
        else:
            with open(file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue

    @staticmethod
    def _flat(r):
        """Winlogbeat nests fields under winlog.event_data; Wazuh under data.win.eventdata; others are flat."""
        w = r.get("winlog") or {}
        if w:
            out = dict(w.get("event_data") or {})
            out.update(EventID=w.get("event_id"), Computer=w.get("computer_name"), TimeCreated=r.get("@timestamp"))
            return out
        w = ((r.get("data") or {}).get("win") or {}) if isinstance(r.get("data"), dict) else {}
        if w:
            out = {k[0].upper() + k[1:]: v for k, v in (w.get("eventdata") or {}).items()}
            s = w.get("system") or {}
            out.update(EventID=s.get("eventID"), Computer=s.get("computer"), TimeCreated=s.get("systemTime"))
            return out
        return r

    def read(self, file):
        rows = []
        for r in self._records(file):
            r = self._flat(r)
            g = lambda *ks: next((str(r[k]) for k in ks if r.get(k) not in (None, "")), "")
            if "Security" not in (g("Channel", "LogName", "Log Name") or "Security"):       # Sysmon, PowerShell and the rest reuse numbers
                continue
            try:
                eid = int(float(g("EventID", "Id", "EventId", "event_id", "Event ID")))
            except ValueError:
                continue
            if eid == 4624:
                lt = g("LogonType", "Logon Type")
                action = {"2": "logon", "7": "logon", "11": "logon", "10": "remote_logon", "3": "remote_logon" if self.o.get("network") else None}.get(lt.strip())
            elif eid == 4663:                                   # object access is audited for everything; only removable storage is kept
                action = "file_to_usb" if g("Task") == "12812" or "removable" in g("Category", "TaskCategory", "Task Category").lower() else None
            else:
                action = _WIN.get(eid)
            if not action:
                continue
            # the account acted upon for logons; the acting account for everything else
            actor = g("TargetUserName", "SubjectUserName") if eid in (4624, 4625, 4634, 4647, 4771) else g("SubjectUserName", "TargetUserName")
            if actor.lower() in _SYSTEM or actor.endswith("$"):
                continue
            ip = g("IpAddress", "SourceAddress")
            obj = {"explicit_cred": g("TargetUserName"), "account_change": g("TargetUserName", "MemberName"),
                   "process": os.path.basename(g("NewProcessName").replace("\\", "/")).lower(),
                   "file_to_usb": g("ObjectName").rsplit(".", 1)[-1].lower()[:8], "remote_logon": ip, "logon_failed": ip}.get(action, "")
            rows.append((g("EventRecordID", "RecordNumber", "RecordId"), g("TimeCreated", "@timestamp", "UtcTime", "TimeGenerated", "Date and Time"),
                         actor.lower(), g("Computer", "Hostname", "host", "MachineName").split(".")[0].upper(), action, obj,
                         bool(ip) and not re.match(r"^(-|::1|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80)", ip)))
            if len(rows) >= 500_000:
                yield self._frame(rows); rows = []
        if rows:
            yield self._frame(rows)

    def _frame(self, rows):
        d = pd.DataFrame(rows, columns=["id", "ts", "actor", "host", "action", "object", "external"])
        ts = pd.to_datetime(d.ts, errors="coerce", utc=True, format="mixed")
        d["ts"] = ts.dt.tz_convert(self.o.get("timezone", "Africa/Addis_Ababa")).dt.tz_localize(None)
        return frame(source="windows", **{c: d[c] for c in d})


class Sshd:
    """Linux /var/log/auth.log or /var/log/secure: sshd accepts and failures, and sudo commands."""
    name = "sshd"
    _line = re.compile(r"^(\w{3}\s+\d+\s[\d:]{8}|\d{4}-\d\d-\d\dT[\d:.+-]+)\s+(\S+)\s+(sshd|sudo)(?:\[\d+\])?:\s+(.*)$")
    _pat = [("logon", re.compile(r"Accepted \S+ for (\S+) from (\S+)")),
            ("logon_failed", re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from (\S+)")),
            ("logon_failed", re.compile(r"Invalid user (\S+) from (\S+)")),
            ("sudo", re.compile(r"^\s*(\S+) : .*COMMAND=(\S+)"))]

    def __init__(self, options=None):
        self.o = options or {}

    def files(self, path):
        return [path] if os.path.isfile(path) else sorted(f for f in glob.glob(os.path.join(path, "**", "*"), recursive=True) if os.path.isfile(f))

    def read(self, file):
        year = str(self.o.get("year", pd.Timestamp.now().year))
        rows = []
        with open(file, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = self._line.match(line)
                if not m:
                    continue
                when, host, _, msg = m.groups()
                for action, p in self._pat:
                    k = p.search(msg)
                    if k:
                        rows.append((when if when[:4].isdigit() else f"{year} {when}", k.group(1), host, action, k.group(2)))
                        break
        if rows:
            d = pd.DataFrame(rows, columns=["ts", "actor", "host", "action", "object"])
            d["ts"] = pd.to_datetime(d.ts, errors="coerce", format="mixed")
            yield frame(source="sshd", external=d.action.ne("sudo") & ~d.object.str.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"), **{c: d[c] for c in d})


class Table:
    """Any delimited file. The workspace config says which column is which:

        {"adapter": "table", "path": "vpn/", "options": {
            "columns": {"ts": "login_time", "actor": "username", "host": "gateway", "object": "client_ip"},
            "action": "remote_logon",                       one action for every row, or
            "action_column": "event", "action_map": {"LOGIN": "logon", "LOGOUT": "logoff"},
            "time_format": "%d/%m/%Y %H:%M", "delimiter": ","}}
    """
    name = "table"

    def __init__(self, options=None):
        self.o = options or {}

    def files(self, path):
        return [path] if os.path.isfile(path) else sorted(glob.glob(os.path.join(path, "**", "*.[ct]sv"), recursive=True))

    def read(self, file):
        o = self.o
        cols = o.get("columns", {})
        for d in pd.read_csv(file, sep=o.get("delimiter", "\t" if file.lower().endswith(".tsv") else ","), dtype=str, chunksize=500_000, encoding_errors="replace"):
            out = {k: d[v] for k, v in cols.items() if v in d}
            if "ts" not in out or "actor" not in out:
                raise ValueError(f"{os.path.basename(file)}: the config must name the time and account columns (found {list(d.columns)})")
            out["ts"] = pd.to_datetime(out["ts"], format=o.get("time_format"), errors="coerce")
            if o.get("action_column") in d:
                out["action"] = d[o["action_column"]].map(o.get("action_map", {})).fillna(d[o["action_column"]].str.lower())
            else:
                out["action"] = o.get("action", "logon")
            yield frame(source=o.get("source", "table"), **out)


ADAPTERS = {a.name: a for a in (Cert, Windows, Sshd, Table)}
