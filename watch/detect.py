"""Scores and reasons.

Detectors look at each person-day, and one number comes out:

    own       how far today's counts sit above this person's own trailing days
    seq       how surprising today's events are to the sequence model (sequence.py)
    peers     how far the counts sit above colleagues in the same role today

On the test data `own` alone ranks best once all five logs are in: adding `seq` or `peers`
found nobody new and cost precision (README, "Measured"). So by default `risk` is `own`, and
the other two are shown beside each alert as second opinions. `sequence_weight` in watch.json
gives the sequence model a share of the ranking, which is worth trying on logs where the
counts are thinner than CERT's.

`risk` is where the day falls among the days the watch learned from, as a percentile of the
detectors' averaged ranks: 99.5 means only one learned day in 200 looked stranger. Days above
the alert percentile make the queue. Every alert carries its reasons in plain words, built
from the same counts that scored it.

Behaviour an analyst marked as expected (say, IT administrators logging on to other people's
machines) is taken out before scoring, so it stops raising alerts.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import COUNTS, HOST_COUNTS

TOP = 2              # a day's `own` score is the sum of its TOP rarest deviations
NOTABLE = 2.0        # a deviation this rare (one learned day in a hundred, for that count) is worth a reason line


def _expected_mask(d, counts, expected):
    """True where a count on a row is covered by an "expected behaviour" rule."""
    m = np.zeros((len(d), len(counts)), dtype=bool)
    for r in expected or []:
        kind, _, val = str(r.get("who", "")).partition(":")
        rows = (d.role.values == val) if kind == "role" else (d.actor.values == val) if kind == "actor" else np.full(len(d), kind == "everyone")
        what = str(r.get("what", ""))
        for j, c in enumerate(counts):                            # one count, a whole log family ("family:usb"), or everything
            if what in (c, "*") or (what.startswith("family:") and c in COUNTS and COUNTS[c][1] == what[7:]):
                m[:, j] |= rows
    return m


def rarity(dev, learned):
    """Deviations are not equally telling: some counts jump about for everyone, others almost never move.
    So each deviation is re-expressed as how seldom that count deviates that much, measured over the
    learned days: -log10 of the share of learned person-days with a deviation at least as large.
    2 = one day in a hundred, 3 = one in a thousand."""
    out = np.zeros(dev.shape, dtype=np.float32)
    for j in range(dev.shape[1]):
        ref = np.sort(dev[learned, j])
        tail = 1 - np.searchsorted(ref, dev[:, j], side="left") / max(len(ref), 1)
        out[:, j] = np.where(dev[:, j] > 0, -np.log10(np.maximum(tail, 1 / max(len(ref), 1))), 0)
    return out


def rescore(d, counts, learned, expected=None, key="actor", context=(), sequence_weight=0.0):
    """Adds <count>_rare, `own`, `peers` and `risk` to a days table. Cheap: run again whenever the
    expected-behaviour rules change. Counts named in `context` are left unscored. `sequence_weight`
    is the sequence model's share of the risk (0 = it is shown beside alerts but does not rank them)."""
    keep = ~_expected_mask(d, counts, expected) if key == "actor" else np.ones((1, len(counts)), dtype=bool)
    keep = keep & ~np.isin(counts, list(context))[None, :]
    E = rarity(np.where(keep, d[[f"{c}_dev" for c in counts]].values, 0), learned)
    d = d.drop(columns=[c for c in d.columns if c.endswith("_rare")])
    d = pd.concat([d, pd.DataFrame(E, index=d.index, columns=[f"{c}_rare" for c in counts])], axis=1)
    d["own"] = np.sort(E, 1)[:, -TOP:].sum(1)
    parts = {"own": 1.0}
    if key == "actor":
        P = rarity(np.where(keep, d[[f"{c}_peer" for c in counts]].values, 0), learned)
        d["peers"] = np.sort(P, 1)[:, -TOP:].sum(1)
        if "seq" in d and float(d.seq.abs().sum()) > 0:
            parts = {"own": 1.0 - sequence_weight, "seq": sequence_weight}
    return fuse(d, parts, learned)


def fuse(d, parts, learned, out="risk"):
    """Weighted average of the detectors' ranks, expressed as a percentile of the learned days.
    A detector with weight 0 still gets its own percentile column, for the console."""
    s = sum(w * d[p].rank(pct=True) for p, w in parts.items()) / sum(parts.values())
    ref = np.sort(s[learned].values)
    d[out + "_raw"] = s.astype("float32")
    d[out] = (np.searchsorted(ref, s.values, side="left") / max(len(ref), 1) * 100).astype("float32")
    for p in parts:                                               # each detector's own percentile, for the console
        r = np.sort(d.loc[learned, p].values)
        d[p + "_pct"] = (np.searchsorted(r, d[p].values, side="left") / max(len(r), 1) * 100).astype("float32")
    return d


def reasons(r, counts, limit=4):
    """Plain-language reasons for one day, strongest first. `r` is a row of a days table (a dict works)."""
    out = []
    for c in sorted(counts, key=lambda c: -float(r.get(f"{c}_rare", 0))):
        rare, x = float(r.get(f"{c}_rare", 0)), float(r[c])
        if rare < NOTABLE or x <= 0 or len(out) >= limit:
            break
        base = r.get(f"{c}_base")
        label = COUNTS[c][0] if c in COUNTS else HOST_COUNTS.get(c, c)
        if c == "listed_web" and r.get("listed"):
            label = f"Visits to listed sites ({r['listed']})"
        if base is None or pd.isna(base):
            out.append(f"{label}: {x:g} today")
        elif base < 0.05:
            out.append(f"{label}: {x:g} today, none in their recent history")
        else:
            out.append(f"{label}: {x:g} today, usually {base:.1f}")
    if float(r.get("seq_pct", 0) or 0) >= 99:
        out.append("The order of today's events is unusual for this person (sequence model)")
    return out or ["No single count stands out; several are a little above usual"]


def evaluate(d, score, learned, quantile=0.99, only=None, name=None, log=print):
    """Against known incidents: ranking quality over test person-days, and what the queue would hold if
    every day above the learned days' `quantile` of the score raised an alert. `only` restricts the
    incident set to some people (for a development / hold-out split); other people's incident days are dropped."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    t = d[~learned]
    if only is not None:
        t = t[~t.bad | t.incident.isin(only)]
    y, s = t.bad.values, t[score].values
    thr = d.loc[learned, score].quantile(quantile)
    flagged = t[t[score] > thr]
    ins = t[t.bad].groupby("incident").agg(first=("day", "min"), scenario=("scenario", "first"))
    hit = flagged[flagged.bad].groupby("incident").day.min()
    lead = (hit - ins["first"].reindex(hit.index)).dt.days
    n_days = max(t.day.nunique(), 1)
    res = {"roc_auc": round(float(roc_auc_score(y, s)), 4), "pr_auc": round(float(average_precision_score(y, s)), 4),
           "base_rate": round(float(y.mean()), 5), "alerts": int(len(flagged)), "alerts_per_day": round(len(flagged) / n_days, 1),
           "precision": round(float(flagged.bad.mean()), 4) if len(flagged) else 0.0,
           "bad_days": int(y.sum()), "bad_days_flagged": int(flagged.bad.sum()),
           "insiders": int(len(ins)), "found": int(len(hit)), "found_first_day": int((lead == 0).sum()), "found_first_week": int((lead <= 7).sum()),
           "by_scenario": {int(k): [int((ins.scenario.reindex(hit.index) == k).sum()), int(v)] for k, v in ins.groupby("scenario").size().items()}}
    if log:
        sc = "  ".join(f"s{k} {a}/{b}" for k, (a, b) in res["by_scenario"].items())
        log(f"{(name or score):22s} AUC {res['roc_auc']:.3f}  PR {res['pr_auc']:.3f}  {res['alerts_per_day']:5.1f} alerts/day  "
            f"found {res['found']}/{res['insiders']} ({res['found_first_day']} first day, {res['found_first_week']} first week)  "
            f"precision {res['precision']:.1%}  {sc}")
    return res
