"""The feature route to UEBA: count what each user did each day, compare it with the
user's own past and with colleagues in the same role, score the difference.

Two scores come out of it:
  zscore    the sum of how far each count sits above the user's own trailing baseline
            (transparent: every alert lists the counts that drove it)
  iforest   Isolation Forest over raw counts, self-deviations and peer-deviations

Usage:  python features.py        (after prepare.py)
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the prototype now lives in attempts/; its data stays in ../data
P = os.path.join(HERE, "data", "prepared")
TRAIN_END = pd.Timestamp("2010-06-01")       # the first red-team activity starts on 2010-06-10
COUNTS = ["logons", "after_hours_logons", "usb", "after_hours_usb", "other_pc_logons", "other_pc_usb", "pcs", "new_pcs", "weekend"]
LABEL = {"logons": "logons", "after_hours_logons": "after-hours logons", "usb": "USB connects", "after_hours_usb": "after-hours USB connects",
         "other_pc_logons": "logons on someone else's PC", "other_pc_usb": "USB on someone else's PC", "pcs": "PCs used",
         "new_pcs": "PCs never used before", "weekend": "weekend activity"}


def user_days():
    ev = pd.read_parquet(os.path.join(P, "events.parquet"))
    users = pd.read_csv(os.path.join(P, "users.csv")).set_index("user")
    after = ev.weekend | (ev.hour < 6) | (ev.hour >= 19)
    lon, usb, oth = ev.activity == "Logon", ev.activity == "Connect", ev["where"] == "other"
    first_use = ev[lon].drop_duplicates(["user", "pc"]).index           # first time this user logs on to this PC
    first_seen = ev.groupby("user")["day"].transform("min")
    ev["new_pc"] = ev.index.isin(first_use) & (ev.day > first_seen + pd.Timedelta(days=14))
    g = ev.assign(logons=lon, after_hours_logons=lon & after, usb=usb, after_hours_usb=usb & after, other_pc_logons=lon & oth,
                  other_pc_usb=usb & oth).groupby(["user", "day"])
    d = g[["logons", "after_hours_logons", "usb", "after_hours_usb", "other_pc_logons", "other_pc_usb", "new_pc", "malicious"]].sum()
    d = d.rename(columns={"new_pc": "new_pcs"})
    d["pcs"] = g["pc"].nunique()
    d["weekend"] = g["weekend"].max().astype(float)
    d["first_hour"] = g["hour"].min(); d["last_hour"] = g["hour"].max()
    d = d.reset_index()
    d["malicious"] = d.malicious > 0
    d["role"] = d.user.map(users.role)
    return d.sort_values(["user", "day"]).reset_index(drop=True), ev


def add_baselines(d):
    """Self: trailing 60 active days, not counting today. Peers: same role, same day."""
    by = d.groupby("user", sort=False)
    for c in COUNTS:
        mean = by[c].transform(lambda s: s.shift(1).rolling(60, min_periods=10).mean())
        std = by[c].transform(lambda s: s.shift(1).rolling(60, min_periods=10).std())
        d[f"{c}_base"] = mean
        d[f"{c}_z"] = ((d[c] - mean) / (std + 0.5)).fillna(0.0)
        peer = d.groupby(["role", "day"])[c]
        d[f"{c}_peer"] = ((d[c] - peer.transform("mean")) / (peer.transform("std").fillna(0) + 0.5)).fillna(0.0)
    d["zscore"] = sum(d[f"{c}_z"].clip(0, 8) for c in COUNTS)
    return d


def evaluate(d, score, name, quantile=0.99):
    """User-day ranking quality, and what the review queue would hold if every user-day above
    the training period's `quantile` of the score raised an alert (no peeking at the test period)."""
    t = d[d.day >= TRAIN_END]
    y, s = t.malicious.values, t[score].values
    thr = d.loc[d.day < TRAIN_END, score].quantile(quantile)
    flagged = t[t[score] > thr]
    ins = pd.read_csv(os.path.join(P, "insiders.csv"), parse_dates=["start", "end"])
    found, lead = 0, []
    for _, r in ins.iterrows():
        hits = flagged[(flagged.user == r.user) & flagged.malicious]
        if len(hits):
            found += 1
            lead.append((hits.day.min() - t[(t.user == r.user) & t.malicious].day.min()).days)
    n_days = t.day.nunique()
    res = {"roc_auc": round(float(roc_auc_score(y, s)), 4), "pr_auc": round(float(average_precision_score(y, s)), 4),
           "base_rate": round(float(y.mean()), 5), "threshold_quantile": quantile, "alerts": int(len(flagged)),
           "alerts_per_day": round(len(flagged) / n_days, 1), "alert_share": round(len(flagged) / len(t), 4),
           "precision": round(float(flagged.malicious.mean()), 4) if len(flagged) else 0.0,
           "malicious_user_days": int(y.sum()), "malicious_user_days_flagged": int(flagged.malicious.sum()),
           "insiders": len(ins), "insiders_found": found, "found_same_day": int(sum(x == 0 for x in lead)),
           "found_by_scenario": {int(k): int(v) for k, v in ins[ins.user.isin(flagged[flagged.malicious].user)].groupby("scenario").size().items()}}
    print(f"{name:10s} ROC-AUC {res['roc_auc']:.3f}  PR-AUC {res['pr_auc']:.3f} (chance {res['base_rate']:.4f})  {res['alerts_per_day']} alerts/day "
          f"({res['alert_share']:.2%} of user-days): {found}/{len(ins)} insiders ({res['found_same_day']} on their first bad day), "
          f"{res['malicious_user_days_flagged']}/{res['malicious_user_days']} bad days, precision {res['precision']:.1%}  {res['found_by_scenario']}")
    return res


def main():
    d, _ = user_days()
    d = add_baselines(d)
    cols = COUNTS + [f"{c}_z" for c in COUNTS] + [f"{c}_peer" for c in COUNTS] + ["first_hour", "last_hour"]
    tr = d.day < TRAIN_END
    iso = IsolationForest(n_estimators=300, max_samples=8192, random_state=0, n_jobs=-1).fit(d.loc[tr, cols].values)
    d["iforest"] = -iso.score_samples(d[cols].values)
    d["random"] = np.random.default_rng(0).random(len(d))
    res = {k: evaluate(d, k, k) for k in ("random", "zscore", "iforest")}
    d.to_parquet(os.path.join(P, "user_days.parquet"))
    json.dump(res, open(os.path.join(P, "results_features.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
