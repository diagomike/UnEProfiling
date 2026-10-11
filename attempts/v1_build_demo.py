"""Export a stretch of the scored CERT r4.2 user-days for the review console and build the page:
attempts/v1_template.html + data -> attempts/v1_demo.html

Usage:  python build_demo.py        (after prepare.py, features.py, logbert.py)
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd

from v1_features import COUNTS, LABEL, P, TRAIN_END

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the prototype now lives in attempts/; its data stays in ../data
WINDOW, TOP = 45, 8


def main():
    ud = pd.read_parquet(os.path.join(P, "user_days.parquet"))
    lb = pd.read_parquet(os.path.join(P, "user_days_logbert.parquet"))[["user", "day", "lb_nll_sum", "lb_miss", "combined"]]
    d = ud.merge(lb, on=["user", "day"])
    users = pd.read_csv(os.path.join(P, "users.csv")).set_index("user")
    ins = pd.read_csv(os.path.join(P, "insiders.csv"), parse_dates=["start", "end"]).set_index("user")
    ev = pd.read_parquet(os.path.join(P, "events.parquet")).merge(pd.read_parquet(os.path.join(P, "event_surprise.parquet")), on="id")

    train = np.sort(d.loc[d.day < TRAIN_END, "combined"].values)
    d["risk"] = np.searchsorted(train, d.combined.values) / len(train) * 100          # percentile against the clean months
    thr = 99.0
    for c in COUNTS:                                                                    # what colleagues in the same role did that day
        d[f"{c}_role"] = d.groupby(["role", "day"])[c].transform("mean")

    test_days = np.sort(d.loc[d.day >= TRAIN_END, "day"].unique())
    bad = d[d.malicious & (d.day >= TRAIN_END)]
    best, start = -1, 0
    for i in range(0, len(test_days) - WINDOW):
        n = bad[(bad.day >= test_days[i]) & (bad.day <= test_days[i + WINDOW - 1])].user.nunique()
        if n > best:
            best, start = n, i
    days = test_days[start:start + WINDOW]
    w = d[d.day.isin(days)].copy()
    w["rank"] = w.groupby("day")["risk"].rank(ascending=False, method="first")
    q = w[w["rank"] <= TOP].sort_values(["day", "rank"])
    evw = ev[ev.day.isin(days) & ev.user.isin(q.user.unique())]
    evg = {k: g for k, g in evw.groupby(["user", "day"])}

    def why(r, e):
        out = []
        base = lambda c: (0.0 if pd.isna(r[f"{c}_base"]) else float(r[f"{c}_base"]))
        if r.usb > 0 and base("usb") < 0.05:
            out.append(f"Used a USB drive {int(r.usb)} time{'s' if r.usb > 1 else ''}; none in their previous 60 working days")
        elif r.usb_z > 3:
            out.append(f"{int(r.usb)} USB connects today; their usual is {base('usb'):.1f} a day")
        if r.after_hours_logons > 0 and base("after_hours_logons") < 0.1:
            t = e[(e.activity == "Logon") & ((e.hour < 6) | (e.hour >= 19) | e.weekend)]
            out.append(f"Logged on after hours{' at ' + t.date.iloc[0].strftime('%H:%M') if len(t) else ''}; they almost never do")
        if r.after_hours_usb > 0 and base("after_hours_usb") < 0.05:
            out.append("USB drive connected after hours")
        if r.other_pc_logons > 0 and base("other_pc_logons") < 0.1:
            pc = e[(e.activity == "Logon") & (e["where"] == "other")].pc
            out.append(f"Logged on to another person's machine{' (' + pc.iloc[0] + ')' if len(pc) else ''}")
        if r.new_pcs > 0:
            out.append("Used a machine they had never used before")
        if r.weekend and base("weekend") < 0.05:
            out.append("Active at the weekend, which is unusual for them")
        if r.logons_z > 4 and not out:
            out.append(f"{int(r.logons)} logons today; their usual is {base('logons'):.1f}")
        top = e.sort_values("surprise", ascending=False).head(1)
        if len(top) and top.surprise.iloc[0] > 4:
            t = top.iloc[0]
            out.append(f"Least expected event for the sequence model: {t.activity.lower()} at {t.date.strftime('%H:%M')} on {'their own' if t['where'] == 'own' else 'a shared' if t['where'] == 'shared' else 'another person’s'} machine")
        return out[:4] or ["No single count stands out; the day's sequence of events is unusual for this user"]

    queue = {}
    for r in q.itertuples(index=False):
        r = pd.Series(r._asdict())
        e = evg.get((r.user, r.day), ev.iloc[:0]).sort_values("date")
        u = users.loc[r.user] if r.user in users.index else None
        queue.setdefault(str(pd.Timestamp(r.day).date()), []).append({
            "u": r.user, "role": (u.role if u is not None else "?"), "dept": (str(u.department).split(" - ")[-1] if u is not None else ""),
            "risk": round(float(r.risk), 2), "mal": bool(r.malicious), "scen": int(ins.scenario.get(r.user, 0)) if r.malicious else 0,
            "why": why(r, e),
            "counts": [[LABEL[c], round(float(r[c]), 1), None if pd.isna(r[f"{c}_base"]) else round(float(r[f"{c}_base"]), 2), round(float(r[f"{c}_role"]), 2)]
                       for c in ("logons", "after_hours_logons", "usb", "after_hours_usb", "other_pc_logons", "pcs")],
            "ev": [[t.strftime("%H:%M"), a, wh, round(float(s), 1)] for t, a, wh, s in zip(e.date, e.activity, e["where"], e.surprise)][:24],
        })
    line = w[w.user.isin(q.user.unique())].pivot_table(index="user", columns="day", values="risk").reindex(columns=days)
    data = {"days": [str(pd.Timestamp(x).date()) for x in days], "threshold": thr, "queue": queue,
            "active": {str(pd.Timestamp(k).date()): int(v) for k, v in w.groupby("day").size().items()},
            "alerts": {str(pd.Timestamp(k).date()): int(v) for k, v in w[w.risk > thr].groupby("day").size().items()},
            "line": {u: [None if pd.isna(v) else round(float(v), 1) for v in row] for u, row in line.iterrows()},
            "results": {**json.load(open(os.path.join(P, "results_features.json"))), **json.load(open(os.path.join(P, "results_logbert.json")))},
            "meta": {"users": int(d.user.nunique()), "user_days": int(len(d)), "events": int(len(ev)), "train_end": str(TRAIN_END.date()),
                     "test_days": int(len(test_days)), "insiders_in_window": int(best)}}
    os.makedirs(os.path.join(HERE, "demo"), exist_ok=True)
    page = open(os.path.join(HERE, "attempts", "v1_template.html"), encoding="utf-8").read().replace("/*DATA*/null", json.dumps(data, separators=(",", ":")))
    open(os.path.join(HERE, "attempts", "v1_demo.html"), "w", encoding="utf-8").write(page)
    print(f"window {data['days'][0]} to {data['days'][-1]}: {best} insiders active, {sum(len(v) for v in queue.values())} queue rows, "
          f"{sum(x['mal'] for v in queue.values() for x in v)} red-team rows, page {len(page) / 1e3:.0f} kB")


if __name__ == "__main__":
    main()
