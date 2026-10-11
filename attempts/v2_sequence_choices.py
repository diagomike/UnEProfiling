"""How should the sequence model's per-event surprise become a day's score, and does adding it to the
count detector help? Tried on the development half of the insiders only. Run after `python -m watch score`."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np, pandas as pd
from watch.workspace import Workspace
from watch import detect, pipeline

ws = Workspace(next((a for a in sys.argv[1:] if not a.startswith("--")), "workspaces/cert-r42"))
d = pd.read_parquet(ws.p("days.parquet"))
learned, until = pipeline.learned_mask(ws, d)
dev, hold = pipeline.halves(d)
s = pd.read_parquet(ws.p("model", "surprise.parquet"))
s["day"] = s.ts.dt.normalize(); s["kind"] = s.tok.str.split("|").str[0]
s = s[s.surprise > 0]
# an event's surprise against what is usual for that kind of event in the learned days
ref = s[s.day < until].groupby("kind").surprise.agg(["mean", "std"])
s["excess"] = ((s.surprise - s.kind.map(ref["mean"])) / (s.kind.map(ref["std"]) + 0.1)).fillna(0)
s["over4"] = np.clip(s.surprise - 4, 0, None); s["over6"] = np.clip(s.surprise - 6, 0, None); s["excess_over2"] = np.clip(s.excess - 2, 0, None)
g = s.groupby(["actor", "day"], sort=False)
s["r"] = g.surprise.rank(ascending=False, method="first"); s["re"] = g.excess.rank(ascending=False, method="first")
agg = g.agg(sum=("surprise", "sum"), max=("surprise", "max"), mean=("surprise", "mean"), over4=("over4", "sum"), over6=("over6", "sum"),
            excess_max=("excess", "max"), excess_over2=("excess_over2", "sum"))
agg["top3"] = s[s.r <= 3].groupby(["actor", "day"], sort=False).surprise.sum()
agg["excess_top3"] = s[s.re <= 3].groupby(["actor", "day"], sort=False).excess.sum()
agg = agg.reset_index()
d = d.merge(agg, on=["actor", "day"], how="left").fillna({c: 0 for c in agg.columns if c not in ("actor", "day")})
ev = lambda col, name: detect.evaluate(d, col, learned, only=dev, name=name)
ev("own", "own baseline alone")
for c in ("sum", "max", "mean", "top3", "over4", "over6", "excess_max", "excess_top3", "excess_over2"):
    ev(c, "sequence: " + c)
print("-- combined with the own baseline")
for c in ("sum", "max", "top3", "over6", "excess_max", "excess_top3", "excess_over2"):
    for w in (0.5, 0.25):
        d["f"] = (1 - w) * d.own.rank(pct=True) + w * d[c].rank(pct=True); ev("f", f"own + {w} x {c}")
    d["f"] = np.maximum(d.own.rank(pct=True), d[c].rank(pct=True)); ev("f", f"max(own, {c})")
if "--save" in sys.argv:
    agg.to_parquet(ws.p("model", "_seq_choices.parquet"))
