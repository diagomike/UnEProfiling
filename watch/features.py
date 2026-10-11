"""From events to behaviour: one row per person and active day (and one per machine and day).

Each row counts what happened that day (COUNTS below), then sets every count against two
yardsticks: the same person's own trailing days, and colleagues in the same role that day.
Nothing here knows which log a count came from; a count whose log is absent is simply
all zero and is left out.

Two passes over the months keep memory flat however large the logs are:
  1. habits that span months: each person's own machine, when they first used each machine,
     site and outside mail domain, and how many people use each site;
  2. the daily counts, using those.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

# count -> (label for the console, the log family it needs)
COUNTS = {
    "logons": ("Logons", "logon"), "off_logons": ("After-hours logons", "logon"), "hosts": ("Machines used", "logon"),
    "other_logons": ("Logons on someone else's machine", "logon"), "new_hosts": ("Machines never used before", "logon"),
    "logon_fails": ("Failed logons", "logon"), "remote_logons": ("Remote logons", "logon"),
    "privileged": ("Privileged sessions", "logon"), "explicit_creds": ("Uses of another account's credentials", "logon"),
    "account_changes": ("Account changes", "logon"),
    "usb": ("USB drive connects", "usb"), "off_usb": ("After-hours USB connects", "usb"), "other_usb": ("USB on someone else's machine", "usb"),
    "files_usb": ("Files copied to USB", "file"), "programs_usb": ("Programs copied to USB", "file"), "off_files_usb": ("After-hours copies to USB", "file"),
    "emails": ("Emails sent", "email"), "ext_emails": ("Emails to outside addresses", "email"),
    "ext_attachments": ("Attachments sent outside", "email"), "new_mail_domains": ("Outside organisations never mailed before", "email"),
    "personal_emails": ("Emails from a personal address", "email"),
    "web": ("Web visits", "web"), "domains": ("Sites visited", "web"), "new_sites": ("Sites never visited before", "web"),
    "rare_web": ("Visits to sites few colleagues use", "web"), "listed_web": ("Visits to listed site categories", "web"),
    "off_web": ("After-hours web visits", "web"),
    "off_events": ("After-hours events of any kind", "any"), "weekend": ("Weekend activity", "any"),
}
HOST_COUNTS = {"h_users": "People who logged on", "h_logons": "Logons", "h_off_logons": "After-hours logons", "h_visitors": "Logons by people whose machine it is not",
               "h_new_users": "People who had never used it", "h_usb": "USB drive connects", "h_files_usb": "Files copied to USB"}
PROGRAMS = {"exe", "msi", "bat", "cmd", "ps1", "vbs", "dll", "scr", "jar"}
WARMUP_DAYS = 21                 # a person's first weeks are all "firsts"; do not count them as new


def _off(ts, hours):
    h = ts.dt.hour
    return ts.dt.dayofweek.isin(hours["weekend"]) | (h < hours["start"]) | (h >= hours["end"])


def habits(ws, log=print):
    """Pass 1. Returns a dict of small tables describing habits that span months."""
    hosts, sites, mail, seen, pop = [], [], [], [], []
    learn_until = pd.Timestamp(ws.cfg["learn_until"]) if ws.cfg.get("learn_until") else None
    for m in ws.months():
        e = ws.read_events(m, columns=["ts", "actor", "host", "action", "object"])
        seen.append(e.groupby("actor", observed=True).ts.min())
        lg = e[e.action.isin(["logon", "remote_logon"])]
        hosts.append(lg.groupby(["actor", "host"], observed=True).ts.agg(["min", "size"]).reset_index())
        w = e[e.action.astype(str).str.startswith("web_")]
        if len(w):
            g = w.groupby(["actor", "object"], observed=True).ts.min().reset_index()
            sites.append(g)
            if learn_until is None or pd.Timestamp(m + "-01") < learn_until:
                pop.append(g[["actor", "object"]])
        em = e[(e.action == "email_send") & (e.object.astype(str) != "")]
        if len(em):
            x = em[["actor", "ts"]].assign(domain=em.object.astype(str).str.split(";")).explode("domain")
            mail.append(x[x.domain.ne("") & x.domain.ne("from-personal")].groupby(["actor", "domain"], observed=True).ts.min().reset_index())
    out = {"first_seen": pd.concat(seen).groupby(level=0).min()}
    h = pd.concat(hosts).groupby(["actor", "host"], observed=True).agg(first=("min", "min"), n=("size", "sum")).reset_index()
    h = h[h.host.astype(str) != ""]
    out["home"] = h.sort_values("n").groupby("actor", observed=True).tail(1).set_index("actor").host.astype(str)
    out["shared"] = set(h.host.astype(str)) - set(out["home"])            # nobody's own machine
    out["host_first"] = h.set_index(["actor", "host"])["first"]
    if sites:
        out["site_first"] = pd.concat(sites).groupby(["actor", "object"], observed=True).ts.min()
        p = pd.concat(pop).drop_duplicates() if pop else pd.concat(sites)[["actor", "object"]].drop_duplicates()
        out["site_users"] = p.groupby("object", observed=True).size()
    if mail:
        out["mail_first"] = pd.concat(mail).groupby(["actor", "domain"], observed=True).ts.min()
    log(f"  habits: {len(out['first_seen']):,} people, {len(out['home']):,} with a machine of their own, {len(out['shared'])} shared machines"
        + (f", {len(out['site_users']):,} sites" if sites else ""))
    return out


def _firsts(table, hab, by="actor"):
    """From a (person, thing) -> first time table: how many things each person (or, with by="host", each
    machine) met for the first time on each day. A person's warm-up weeks do not count."""
    t = table.reset_index()
    t.columns = ["actor", "thing", "ts"]
    t = t[t.ts > t.actor.astype(str).map(hab["first_seen"]) + pd.Timedelta(days=WARMUP_DAYS)]
    if by == "host":
        t = t[t.thing.astype(str) != t.actor.astype(str).map(hab["home"])]
        return t.groupby([t.thing.astype(str).rename("host"), t.ts.dt.normalize().rename("day")]).size()
    return t.groupby([t.actor.astype(str).rename("actor"), t.ts.dt.normalize().rename("day")]).size()


def daily(ws, hab, log=print):
    """Pass 2. Returns (days, host_days): the daily counts per person and per machine."""
    hours = ws.cfg["hours"]
    listed = {d.lower(): cat for cat, ds in ws.cfg["sites"].items() for d in ds}
    n_people = len(hab["first_seen"])
    rare = set(hab["site_users"][hab["site_users"] <= max(2, 0.01 * n_people)].index.astype(str)) if "site_users" in hab else set()
    known = set(hab["site_users"].index.astype(str)) if "site_users" in hab else set()
    days, hdays = [], []
    for m in ws.months():
        e = ws.read_events(m, columns=["ts", "actor", "host", "action", "object", "amount", "external"])
        for c in ("actor", "host", "action"):                       # `object` stays categorical: a month of web visits is large
            e[c] = e[c].astype(str)
        e["day"] = e.ts.dt.normalize()
        off = _off(e.ts, hours)
        a = e.action
        lon = a.isin(["logon", "remote_logon"])
        home = e.actor.map(hab["home"])
        other = e.host.ne("") & e.host.ne(home) & ~e.host.isin(hab["shared"])
        usb, fil, em, web = a == "usb_connect", a == "file_to_usb", a == "email_send", a.str.startswith("web_")
        f = pd.DataFrame({"actor": e.actor, "day": e.day})
        f["logons"] = lon; f["off_logons"] = lon & off; f["other_logons"] = lon & other
        f["logon_fails"] = a == "logon_failed"; f["remote_logons"] = a == "remote_logon"; f["privileged"] = a == "privileged"
        f["explicit_creds"] = a == "explicit_cred"; f["account_changes"] = a == "account_change"
        f["usb"] = usb; f["off_usb"] = usb & off; f["other_usb"] = usb & other
        f["files_usb"] = fil; f["programs_usb"] = fil & e.object.isin(PROGRAMS); f["off_files_usb"] = fil & off
        f["emails"] = em; f["ext_emails"] = em & e.external; f["ext_attachments"] = np.where(em & e.external, e.amount, 0)
        f["personal_emails"] = em & e.object.str.startswith("from-personal")
        f["web"] = web; f["off_web"] = web & off
        f["rare_web"] = web & (e.object.isin(rare) | ~e.object.isin(known))
        cat = e.object.astype(object).map(listed).where(web)
        f["listed_web"] = cat.notna()
        f["off_events"] = off & ~a.isin(["logoff", "usb_disconnect"])
        g = f.groupby(["actor", "day"], sort=False)
        d = g.sum(numeric_only=True)
        d["hosts"] = e[lon & e.host.ne("")].groupby(["actor", "day"]).host.nunique()
        d["domains"] = e[web].groupby(["actor", "day"]).object.nunique()
        d["weekend"] = e.groupby(["actor", "day"]).ts.first().dt.dayofweek.isin(hours["weekend"]).astype(float)
        hr = e.ts.dt.hour + e.ts.dt.minute / 60
        d["first_hour"] = hr.groupby([e.actor, e.day]).min(); d["last_hour"] = hr.groupby([e.actor, e.day]).max()
        d["events"] = g.size()
        if cat.notna().any():                                        # which listed categories, for the reason line
            c2 = pd.DataFrame({"actor": e.actor, "day": e.day, "cat": cat}).dropna().drop_duplicates()
            d["listed"] = c2.groupby(["actor", "day"]).cat.agg(lambda s: "; ".join(sorted(s)))
        days.append(d.reset_index())

        h = e[e.host.ne("")]
        if len(h):
            hl = h.action.isin(["logon", "remote_logon"])
            hf = pd.DataFrame({"host": h.host, "day": h.day, "h_logons": hl, "h_off_logons": hl & off[h.index],
                               "h_visitors": hl & other[h.index], "h_usb": h.action == "usb_connect", "h_files_usb": h.action == "file_to_usb"})
            hd = hf.groupby(["host", "day"], sort=False).sum(numeric_only=True)
            hd["h_users"] = h[hl].groupby(["host", "day"]).actor.nunique()
            hdays.append(hd.reset_index())
        log(f"  {m}: {len(e):,} events, {len(d):,} person-days")
    d = pd.concat(days, ignore_index=True).set_index(["actor", "day"])
    d["new_hosts"] = _firsts(hab["host_first"], hab)                 # firsts come straight from the habit tables
    if "site_first" in hab:
        d["new_sites"] = _firsts(hab["site_first"], hab)
    if "mail_first" in hab:
        d["new_mail_domains"] = _firsts(hab["mail_first"], hab)
    d = d.reset_index()
    for c in COUNTS:
        d[c] = d[c].fillna(0).astype("float32") if c in d else np.float32(0)
    d["listed"] = d["listed"].fillna("") if "listed" in d else ""
    if hdays:
        hd = pd.concat(hdays, ignore_index=True).set_index(["host", "day"])
        hd["h_new_users"] = _firsts(hab["host_first"], hab, by="host")
        hd = hd.fillna(0).reset_index()
    else:
        hd = pd.DataFrame(columns=["host", "day"])
    return d.sort_values(["actor", "day"]).reset_index(drop=True), hd.sort_values(["host", "day"]).reset_index(drop=True)


def _unlikely(x, mean, std, n):
    """How unlikely is a count this high, as -log10 of its chance: 2 means one day in a hundred.

    Two readings, and the more cautious one wins. Rare things (a first USB drive, a first night
    logon) are judged as a Poisson count against the usual rate, so "never before" is strong
    evidence but one event is not infinite evidence. Busy, bursty counts (web visits, emails) are
    judged against their own spread, which a Poisson would understate."""
    from scipy.stats import norm, poisson
    lam = (mean * n + 0.5) / (n + 1)                              # half an event of doubt, so the rate is never exactly zero
    pois = -poisson.logsf(np.ceil(x) - 1, lam) / np.log(10)
    gauss = -norm.logsf((x - mean) / (std + 0.1)) / np.log(10)
    out = np.minimum(pois, gauss)
    return np.where((x > mean) & (x > 0), np.nan_to_num(out, nan=0.0, posinf=20.0), 0.0)


def against_self(d, cols, key="actor", window=60, min_days=10):
    """For every count: the trailing mean over the entity's last `window` active days (today excluded),
    and how unlikely today's count is against it. Adds <count>_base and <count>_dev."""
    prev = d.groupby(key, sort=False)[cols].shift(1)
    roll = prev.groupby(d[key], sort=False).rolling(window, min_periods=min_days)
    mean = roll.mean().reset_index(level=0, drop=True).reindex(d.index)
    std = roll.std().reset_index(level=0, drop=True).reindex(d.index)
    n = roll.count().reset_index(level=0, drop=True).reindex(d.index)
    dev = pd.DataFrame(_unlikely(d[cols].values.astype(float), mean.values, std.values, n.values), index=d.index, columns=cols).fillna(0.0)
    dev[mean.isna().values] = 0.0                                 # too little history to judge
    return pd.concat([d, mean.add_suffix("_base").astype("float32"), dev.add_suffix("_dev").astype("float32")], axis=1)


def against_peers(d, cols, group="role"):
    """How unlikely each count is among colleagues in the same role on the same day. Adds <count>_peer and <count>_role."""
    g = d.groupby([group, "day"], sort=False)[cols]
    mean, std, n = g.transform("mean"), g.transform("std").fillna(0), d.groupby([group, "day"], sort=False)[group].transform("size").values
    dev = pd.DataFrame(_unlikely(d[cols].values.astype(float), mean.values, std.values, n[:, None]), index=d.index, columns=cols)
    dev[n < 5] = 0.0                                     # a role of three people is not a peer group
    return pd.concat([d, mean.add_suffix("_role").astype("float32"), dev.add_suffix("_peer").astype("float32")], axis=1)


def build(ws, log=print):
    """Events -> days.parquet and hosts.parquet (counts and baselines; scores are added by detect.py)."""
    hab = habits(ws, log)
    d, hd = daily(ws, hab, log)
    who = ws.directory()
    d["role"] = d.actor.map(who.role).fillna("").replace("", "unknown") if "role" in who else "unknown"
    present = [c for c in COUNTS if d[c].abs().sum() > 0]
    d = d.drop(columns=[c for c in COUNTS if c not in present])
    d = against_self(d, present, window=ws.cfg["baseline_days"])
    d = against_peers(d, present)
    if len(hd):
        hd = against_self(hd, list(HOST_COUNTS), key="host", window=ws.cfg["baseline_days"])
        hd["owner"] = hd.host.map({v: k for k, v in hab["home"].items()}).fillna("")
    lab = ws.p("labels.parquet")
    if os.path.exists(lab):                                           # known incidents, by person and day
        L = pd.read_parquet(lab)
        L["day"] = L.ts.dt.normalize()
        if "incident" not in L:
            L["incident"] = L.actor
        t = L.groupby(["actor", "day"]).agg(scenario=("scenario", "first"), incident=("incident", "first"), bad_events=("id", "size")).reset_index()
        d = d.merge(t, on=["actor", "day"], how="left")
        d["bad"] = d.bad_events.notna()
        d["scenario"] = d.scenario.fillna(0).astype(int); d["bad_events"] = d.bad_events.fillna(0).astype(int); d["incident"] = d.incident.fillna("")
    else:
        d["bad"] = False; d["scenario"] = 0; d["bad_events"] = 0; d["incident"] = ""
    return d, hd, present, hab
