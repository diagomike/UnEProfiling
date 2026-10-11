"""Which way of adding up deviations works best? Tried on HALF of the insiders (the development
half); the other half is only used for the final table. Run after `python -m watch score`."""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np, pandas as pd
from watch.workspace import Workspace
from watch import detect

ws = Workspace(next((a for a in sys.argv[1:] if not a.startswith("--")), "workspaces/cert-r42"))
d = pd.read_parquet(ws.p("days.parquet"))
counts = [c[:-4] for c in d.columns if c.endswith("_dev")]
learned = (d.day < pd.Timestamp(ws.cfg["learn_until"])).values
ins = sorted(d[d.bad].incident.unique())
dev = {a for a in ins if int(hashlib.md5(a.encode()).hexdigest(), 16) % 2 == 0}
print(len(ins), "insiders;", len(dev), "in the development half", "| counts:", counts)
if "--volume" not in sys.argv:                        # totals of busy channels are constant per person in CERT: a give-away, left out
    counts = [c for c in counts if c not in ws.cfg["context_only"]]
Z = d[[f"{c}_dev" for c in counts]].values; P = d[[f"{c}_peer" for c in counts]].values
def add(name, v): d[name] = v; detect.evaluate(d, name, learned, only=dev)
add("random", np.random.default_rng(0).random(len(d)))
for fl in (0, 1, 1.3, 2, 3):
    for cap in (4, 6, 10):
        add(f"own: sum dev>={fl} cap {cap}", np.where(Z >= fl, np.minimum(Z, cap), 0).sum(1))
add("own: max", Z.max(1))
add("own: top3", np.sort(np.minimum(Z, 6), 1)[:, -3:].sum(1))
for fl in (1.3, 2, 3):
    add(f"peers: sum dev>={fl} cap 6", np.where(P >= fl, np.minimum(P, 6), 0).sum(1))
if "--each" in sys.argv:
    for c in counts:
        add("only " + c, d[f"{c}_dev"].values)
# Empirical version: how rare is a deviation this high for THIS count among the learned days?
E = np.zeros_like(Z)
for j in range(Z.shape[1]):
    ref = np.sort(Z[learned, j])
    tail = 1 - np.searchsorted(ref, Z[:, j], side="left") / len(ref)          # share of learned days at or above
    E[:, j] = np.where(Z[:, j] > 0, -np.log10(np.maximum(tail, 1 / len(ref))), 0)
for fl in (0, 1, 1.5, 2, 2.5):
    for cap in (4, 6):
        add(f"rarity: sum>={fl} cap {cap}", np.where(E >= fl, np.minimum(E, cap), 0).sum(1))
add("rarity: max", E.max(1))
add("rarity: top2", np.sort(E, 1)[:, -2:].sum(1))
add("rarity: top3", np.sort(E, 1)[:, -3:].sum(1))
