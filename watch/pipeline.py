"""The batch side: read new logs, rebuild behaviour, score, measure.

    read     whatever is new in the sources -> events/
    score    events -> days.parquet, hosts.parquet (counts, baselines, sequence scores, risk)
    measure  against known incidents, if the watch has any -> measured.json

A daily job is `python -m watch update <folder>`: read, then score. The sequence model is
trained once and reused; `--retrain` rebuilds it (do that when new log sources are added).
"""
from __future__ import annotations

import hashlib
import os
import time

import numpy as np
import pandas as pd

from . import detect, features
from .workspace import Workspace, read_json, write_json


def learned_mask(ws, d):
    """The days the watch learns thresholds from: before `learn_until`, or the first 40% of days if unset."""
    until = pd.Timestamp(ws.cfg["learn_until"]) if ws.cfg.get("learn_until") else pd.Series(d.day.unique()).quantile(0.4)
    return (d.day < until).values, pd.Timestamp(until)


def score(ws: Workspace, sequence=True, retrain=False, log=print):
    t0 = time.time()
    d, hd, counts, hab = features.build(ws, log)
    if sequence:
        try:
            from . import sequence as seq
            d = seq.run(ws, d, hab, retrain=retrain, log=log)
        except ImportError as e:                                  # no PyTorch here: the count detectors still work
            log(f"  sequence model skipped ({e.name} is not installed)")
    learned, until = learned_mask(ws, d)
    d = detect.rescore(d, counts, learned, ws.cfg.get("expected"), context=ws.cfg["context_only"], sequence_weight=ws.cfg["sequence_weight"])
    d.to_parquet(ws.p("days.parquet"), index=False)
    if len(hd):
        hl = (hd.day < until).values
        hd = detect.rescore(hd, list(features.HOST_COUNTS), hl, key="host")
        hd.to_parquet(ws.p("hosts.parquet"), index=False)
    meta = {"scored": time.strftime("%Y-%m-%d %H:%M"), "counts": counts, "learn_until": str(until.date()),
            "first_day": str(d.day.min().date()), "last_day": str(d.day.max().date()), "people": int(d.actor.nunique()),
            "person_days": int(len(d)), "machines": int(hd.host.nunique()) if len(hd) else 0,
            "events": int(d.events.sum()), "sources": sorted({features.COUNTS[c][1] for c in counts} - {"any"}),
            "sequence": bool("seq" in d and float(d.seq.sum()) > 0), "seconds": round(time.time() - t0)}
    write_json(ws.p("scored.json"), meta)
    log(f"scored {meta['person_days']:,} person-days for {meta['people']:,} people in {meta['seconds']}s")
    return d, hd, meta


def halves(d):
    """Split the known incidents in two by a hash of their name: design choices were made looking at the
    first half only, so the second is a fair test."""
    ins = sorted(x for x in d.loc[d.bad, "incident"].unique() if x)
    dev = {a for a in ins if int(hashlib.md5(a.encode()).hexdigest(), 16) % 2 == 0}
    return dev, set(ins) - dev


def measure(ws: Workspace, d=None, log=print):
    """How the detectors do against the watch's known incidents."""
    d = pd.read_parquet(ws.p("days.parquet")) if d is None else d
    if not d.bad.any():
        log("no known incidents in this watch; nothing to measure against")
        return None
    learned, until = learned_mask(ws, d)
    q = ws.cfg["alert_percentile"] / 100
    d = d.copy()
    d["random"] = np.random.default_rng(0).random(len(d))
    dev, hold = halves(d)
    has_seq = "seq" in d and float(d.seq.sum()) > 0
    rows = [("random", "Random order"), ("peers", "Role peers (counts against colleagues)")]
    if has_seq:
        rows.append(("seq", "Sequence model (LogBERT) alone"))
        d["own+seq"] = 0.75 * d.own.rank(pct=True) + 0.25 * d.seq.rank(pct=True)
        rows.append(("own+seq", "Own baseline + sequence model (3:1)"))
    rows.append(("own", "Own baseline (counts against own history)"))
    queue = "risk_raw" if ws.cfg["sequence_weight"] else "own"            # what the console's queue is ranked on
    out = {"learn_until": str(until.date()), "alert_percentile": ws.cfg["alert_percentile"], "incidents": len(dev) + len(hold),
           "held_out": len(hold), "test_days": int(d.loc[~learned, "day"].nunique()), "detectors": []}
    for col, label in rows:
        if col not in d:
            continue
        out["detectors"].append({"key": col, "label": label, "queue": col == queue,
                                 "all": detect.evaluate(d, col, learned, q, name=label, log=log),
                                 "held_out": detect.evaluate(d, col, learned, q, only=hold, log=None)})
    write_json(ws.p("measured.json"), out)
    return out


def update(ws: Workspace, log=print, **kw):
    log(f"reading new logs into {ws.dir}")
    n = ws.ingest(log)
    log(f"{n:,} new events")
    if n or not os.path.exists(ws.p("days.parquet")):
        d, hd, meta = score(ws, log=log, **kw)
        if d.bad.any():
            measure(ws, d, log)
    return n
