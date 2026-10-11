"""CERT r4.2 logon + removable-device logs -> one event table and one row per user-day.

Each event becomes a small token ("what, when in the day, on whose machine") so the same
table feeds both detectors: the feature baseline (features.py) and the sequence model
(logbert.py). Labels come from the red-team answer key, matched by event id.

Usage:  python prepare.py
"""
from __future__ import annotations

import glob
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the prototype now lives in attempts/; its data stays in ../data
RAW = os.path.join(HERE, "data", "cert_r4.2")
ANS = os.path.join(HERE, "data", "answers")
OUT = os.path.join(HERE, "data", "prepared")

BUCKETS = ["night", "early", "work", "evening"]          # 22-06, 06-08, 08-18, 18-22


def bucket(hour):
    return np.select([(hour >= 22) | (hour < 6), hour < 8, hour < 18], [0, 1, 2], 3)


def main():
    os.makedirs(OUT, exist_ok=True)
    ev = []
    for name in ("logon", "device"):
        d = pd.read_csv(os.path.join(RAW, f"{name}.csv"))
        d["date"] = pd.to_datetime(d["date"], format="%m/%d/%Y %H:%M:%S")
        ev.append(d)
    ev = pd.concat(ev, ignore_index=True).sort_values(["date", "id"], kind="stable").reset_index(drop=True)
    ev["day"] = ev["date"].dt.normalize()
    ev["hour"] = ev["date"].dt.hour

    # Whose machine? A user's own PC is the one they log on to most; a PC that is nobody's main machine is shared.
    lg = ev[ev.activity == "Logon"]
    own = lg.groupby(["user", "pc"]).size().reset_index(name="n").sort_values("n").groupby("user").tail(1).set_index("user")["pc"]
    shared = set(lg.pc.unique()) - set(own.values)          # nobody's main machine
    ev["where"] = np.where(ev.pc == ev.user.map(own), "own", np.where(ev.pc.isin(shared), "shared", "other"))
    ev["weekend"] = ev["date"].dt.dayofweek >= 5
    ev["token"] = ev.activity + "|" + np.array(BUCKETS)[bucket(ev.hour.values)] + "|" + ev["where"] + np.where(ev.weekend, "|we", "")

    # Labels: red-team events for this release, by event id.
    bad = set()
    for f in glob.glob(os.path.join(ANS, "r4.2-*", "*.csv")):
        for line in open(f, encoding="utf-8", errors="ignore"):
            p = line.split(",", 2)
            if p[0] in ("logon", "device"):
                bad.add(p[1])
    ev["malicious"] = ev.id.isin(bad)
    ins = pd.read_csv(os.path.join(ANS, "insiders.csv"))
    ins = ins[ins.dataset.astype(str) == "4.2"][["user", "scenario", "start", "end"]]
    ins["start"] = pd.to_datetime(ins["start"]); ins["end"] = pd.to_datetime(ins["end"])
    ins.to_csv(os.path.join(OUT, "insiders.csv"), index=False)

    # Who is who: role and department from the first directory snapshot a user appears in.
    ldap = pd.concat([pd.read_csv(f).assign(month=os.path.basename(f)[:7]) for f in sorted(glob.glob(os.path.join(RAW, "LDAP", "*.csv")))])
    who = ldap.sort_values("month").groupby("user_id").agg(role=("role", "first"), department=("department", "first"),
                                                           functional_unit=("functional_unit", "first"), last_month=("month", "last"))
    who.index.name = "user"
    who["own_pc"] = own
    who.to_csv(os.path.join(OUT, "users.csv"))

    ev[["id", "date", "day", "hour", "user", "pc", "activity", "where", "weekend", "token", "malicious"]].to_parquet(os.path.join(OUT, "events.parquet"))
    ud = ev.groupby(["user", "day"]).agg(n=("id", "size"), malicious=("malicious", "max")).reset_index()
    print(f"{len(ev):,} events, {ev.user.nunique()} users, {ev.day.nunique()} days, {len(ud):,} user-days "
          f"({ud.n.mean():.1f} events each), {ev.token.nunique()} tokens")
    print(f"red-team: {int(ev.malicious.sum())} events on {int(ud.malicious.sum())} user-days by {ev[ev.malicious].user.nunique()} of {len(ins)} insiders")
    print(ev.groupby("where").size().to_dict(), "| shared PCs:", len(shared))


if __name__ == "__main__":
    main()
