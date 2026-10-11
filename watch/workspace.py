"""A watch is a folder.

Everything about one monitored organisation lives in one folder of plain files, so it can
sit on a shared drive, be backed up by copying, and be opened by any copy of this app:

    watch.json          the configuration: log sources, working hours, analysts, site lists,
                        behaviour marked as expected, thresholds
    directory.csv       who is who: account, name, role, department, manager
    events/<month>/     the logs, normalised to one table (events.py), one file per source and month
    days.parquet        one row per person and active day: counts, baselines, scores
    hosts.parquet       the same per machine
    model/              the sequence model
    labels.parquet      known incidents (an answer key, or cases confirmed here), to measure against
    cases.jsonl         every decision an analyst took on an alert, appended, never rewritten
    audit.jsonl         every time an analyst opened a person's record or revealed a name

Paths in watch.json may be relative to the folder.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import threading
import time
import uuid

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .adapters import ADAPTERS

DEFAULTS = {
    "name": "", "id": "",
    "sources": [],
    "hours": {"start": 7, "end": 19, "weekend": [5, 6]},       # weekday numbers, Monday = 0
    "baseline_days": 60,                                       # a person is compared with their own last N active days
    "learn_until": None,                                       # the model and the alert threshold learn from before this date
    "alert_percentile": 99.0,
    "sequence_weight": 0.0,                                    # the sequence model's share of the risk; 0 = shown, not ranked on
    "context_only": ["web", "emails"],                         # shown beside an alert but never scored: sheer volume (see README, "A trap in the test data")
    "sites": {                                                 # site categories a proxy would give; edit freely
        "Job search": ["monster.com", "indeed.com", "careerbuilder.com", "linkedin.com", "simplyhired.com", "craigslist.org",
                       "jobhuntersbible.com", "job-hunt.org", "glassdoor.com", "hotjobs.yahoo.com", "ethiojobs.net"],
        "Leak and paste sites": ["wikileaks.org", "pastebin.com", "cryptome.org"],
        "Personal cloud storage": ["dropbox.com", "mega.nz", "wetransfer.com", "drive.google.com", "onedrive.live.com", "mediafire.com"],
        "Monitoring and hacking tools": ["refog.com", "spectorsoft.com", "relytec.com", "wellresearchedreviews.com", "softactivity.com",
                                         "actualkeylogger.com", "best-spy-soft.com", "webwatchernow.com"],
    },
    "analysts": ["Analyst 1", "Analyst 2", "Supervisor"],
    "pseudonyms": True,                                        # show codes, not names, until an analyst gives a reason
    "expected": [],                                            # behaviour marked as normal: {"who": "role:ITAdmin", "what": "other_logons", ...}
    "dismiss_reasons": ["Known administrative work", "Approved overtime or shift", "Travel or remote work", "New role or project",
                        "Checked with manager: explained", "Other"],
    "reveal_reasons": ["Alert under review", "Escalated case", "Request from security lead", "Audit"],
}
_lock = threading.Lock()


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    tmp = f"{path}.{uuid.uuid4().hex[:6]}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


class Workspace:
    def __init__(self, folder):
        self.dir = os.path.abspath(folder)
        if not os.path.exists(self.p("watch.json")):
            raise FileNotFoundError(f"{self.dir} is not a watch folder (no watch.json)")
        self.reload()

    # ---- the folder
    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def resolve(self, path):
        return path if os.path.isabs(path) else os.path.normpath(self.p(path))

    def reload(self):
        self.cfg = {**DEFAULTS, **(read_json(self.p("watch.json")) or {})}
        self.cfg["hours"] = {**DEFAULTS["hours"], **self.cfg.get("hours", {})}

    def save(self):
        with _lock:
            write_json(self.p("watch.json"), self.cfg)

    @staticmethod
    def create(folder, name, sources=None, **extra):
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "watch.json")
        if os.path.exists(path):
            raise FileExistsError(f"{folder} already holds a watch")
        cfg = {**DEFAULTS, "name": name, "id": uuid.uuid4().hex[:10], "created": time.strftime("%Y-%m-%d %H:%M"),
               "sources": sources or [], **extra}
        write_json(path, cfg)
        return Workspace(folder)

    # ---- people
    def directory(self) -> pd.DataFrame:
        f = self.p("directory.csv")
        d = pd.read_csv(f, dtype=str).fillna("") if os.path.exists(f) else pd.DataFrame(columns=["actor"])
        for c in ("name", "role", "department", "team", "manager", "left"):
            if c not in d:
                d[c] = ""
        return d.set_index("actor")

    def code(self, actor) -> str:
        """A stable stand-in for a person's identity. The same person always gets the same code in this
        watch; another watch gives another. Not reversible without the directory."""
        return "P-" + hashlib.blake2s(f"{self.cfg['id']}:{actor}".encode(), digest_size=3).hexdigest().upper()

    # ---- events
    def months(self):
        return sorted(os.path.basename(m) for m in glob.glob(self.p("events", "*")) if os.path.isdir(m))

    def month_files(self, month):
        return sorted(glob.glob(self.p("events", month, "*.parquet")))

    def read_events(self, month, columns=None, actor=None, host=None, as_category=("actor", "host", "action", "object", "source")):
        """One month of events. With `actor` or `host`, only the row groups holding them are read."""
        out = []
        flt = [("actor", "==", actor)] if actor else [("host", "==", host)] if host else None
        for f in self.month_files(month):
            cat = [c for c in as_category if columns is None or c in columns]
            out.append(pq.read_table(f, columns=columns, filters=flt, read_dictionary=cat).to_pandas())
        if not out:
            return pd.DataFrame(columns=columns or [])
        return pd.concat(out, ignore_index=True) if len(out) > 1 else out[0]

    def ingest(self, log=print):
        """Read whatever is new in every source into events/<month>/. Returns the number of events added."""
        manifest = read_json(self.p("events", "_read.json"), {})
        added, touched = 0, set()
        for src in self.cfg["sources"]:
            ad = ADAPTERS[src["adapter"]](src.get("options"))
            path = self.resolve(src["path"])
            seen = manifest.setdefault(src["name"], {})
            for f in ad.files(path):
                sig = f"{os.path.getsize(f)}:{int(os.path.getmtime(f))}"
                key = os.path.relpath(f, path) if os.path.isdir(path) else os.path.basename(f)
                if seen.get(key) == sig:
                    continue
                n = 0
                for chunk in ad.read(f):
                    if not len(chunk):
                        continue
                    for month, part in chunk.groupby(chunk.ts.dt.strftime("%Y-%m")):
                        os.makedirs(self.p("events", month), exist_ok=True)
                        part.to_parquet(self.p("events", month, f"{src['name']}.{uuid.uuid4().hex[:8]}.piece"), index=False)
                        touched.add((month, src["name"]))
                    n += len(chunk)
                seen[key] = sig; added += n
                log(f"  {src['name']}: {key}  {n:,} events")
            if hasattr(ad, "directory"):
                who = ad.directory(path)
                if who is not None:
                    who.to_csv(self.p("directory.csv"), index=False)
            if hasattr(ad, "labels"):
                lab = ad.labels(path)
                if lab is not None:
                    lab.to_parquet(self.p("labels.parquet"), index=False)
        for month, name in sorted(touched):                     # one sorted file per source and month
            pieces = glob.glob(self.p("events", month, f"{name}.*.piece"))
            whole = self.p("events", month, f"{name}.parquet")
            d = pd.concat([pd.read_parquet(x) for x in pieces + ([whole] if os.path.exists(whole) else [])], ignore_index=True)
            d = d[~d.id.duplicated() | d.id.eq("")].sort_values(["actor", "ts"], kind="stable")
            pq.write_table(pa.Table.from_pandas(d, preserve_index=False), whole + ".tmp", row_group_size=20_000, use_dictionary=True)
            os.replace(whole + ".tmp", whole)
            for x in pieces:
                os.remove(x)
        if self.cfg["sources"]:
            os.makedirs(self.p("events"), exist_ok=True)
            write_json(self.p("events", "_read.json"), manifest)
        return added

    # ---- what analysts decide, and who looked at whom
    def _append(self, name, rec):
        rec = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), **rec}
        with _lock, open(self.p(name), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def _lines(self, name):
        try:
            with open(self.p(name), encoding="utf-8") as f:
                return [json.loads(x) for x in f if x.strip()]
        except OSError:
            return []

    def decide(self, **rec):
        return self._append("cases.jsonl", rec)

    def decisions(self):
        return self._lines("cases.jsonl")

    def audit(self, **rec):
        return self._append("audit.jsonl", rec)

    def audits(self):
        return self._lines("audit.jsonl")
