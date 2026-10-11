"""The sequence route to UEBA: LogBERT (Guo, Yuan & Wu, 2021) adapted from system logs
to people.

LogBERT learns what normal log sequences look like with two self-supervised tasks and
no labels: predict masked log keys (MLKP), and pull every normal sequence's summary
vector towards one centre (VHM, volume of hypersphere minimisation). A sequence whose
masked keys the model cannot guess, or whose summary sits far from the centre, is anomalous.

Adaptation to users. A system-log session is long and anonymous; a user's day in the
CERT logs is about four events and only means something relative to that person. So
each sequence is:

    [CLS] role, habits (USB / after-hours / other-PC, from the trailing 60 days) [SEP]
          the user's last 16 events before today [SEP] today's events

Only today's events are scored; the profile and the recent history are context. The
model is trained on the months before any red-team activity (as LogBERT assumes), on a
laptop CPU.

Usage:  python logbert.py        (after prepare.py and features.py)
"""
from __future__ import annotations

import json
import os
import time

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from transformers import BertConfig, BertForMaskedLM

from v1_features import P, TRAIN_END, evaluate

CTX, DAY_MAX, L = 16, 40, 64
PAD, CLS, SEP, MASK = 0, 1, 2, 3
G = 5              # a masked event is a "miss" when the true key is not among the model's top G guesses
ALPHA = 0.1        # weight of the hypersphere term
torch.manual_seed(0); np.random.seed(0)
torch.set_num_threads(min(16, os.cpu_count() or 4))


def habit(x, lo):
    return np.where(x.isna(), "unk", np.where(x <= 0, "none", np.where(x < lo, "low", "high")))


def build():
    ev = pd.read_parquet(os.path.join(P, "events.parquet")).sort_values(["user", "date"], kind="stable").reset_index(drop=True)
    ud = pd.read_parquet(os.path.join(P, "user_days.parquet"))
    vocab = ["[PAD]", "[CLS]", "[SEP]", "[MASK]"] + sorted(ev.token.unique())
    extra = [f"role={r}" for r in sorted(ud.role.dropna().unique())] + ["role=?"] + \
            [f"{k}={v}" for k in ("usb", "afterhours", "otherpc") for v in ("unk", "none", "low", "high")]
    vocab += extra
    idx = {t: i for i, t in enumerate(vocab)}
    tok = ev.token.map(idx).values.astype(np.int16)
    # each user-day is a contiguous slice [a, b) of the user's events
    key = ev.user + "|" + ev.day.astype(str)
    start = np.flatnonzero(np.r_[True, key.values[1:] != key.values[:-1]])
    end = np.r_[start[1:], len(ev)]
    ustart = pd.Series(np.arange(len(ev))).groupby(ev.user.values).transform("min").values
    days = pd.DataFrame({"user": ev.user.values[start], "day": ev.day.values[start], "a": start, "b": end, "u0": ustart[start]})
    days = days.merge(ud[["user", "day", "malicious", "role", "usb_base", "after_hours_logons_base", "other_pc_logons_base"]], on=["user", "day"], how="left")
    prof = np.stack([days.role.fillna("?").map(lambda r: idx[f"role={r}"]).values,
                     np.array([idx[f"usb={h}"] for h in habit(days.usb_base, 0.5)]),
                     np.array([idx[f"afterhours={h}"] for h in habit(days.after_hours_logons_base, 0.2)]),
                     np.array([idx[f"otherpc={h}"] for h in habit(days.other_pc_logons_base, 0.2)])], 1)
    N = len(days)
    ids = np.zeros((N, L), dtype=np.int16)
    today = np.zeros((N, L), dtype=bool)        # positions of today's events
    pos_ev = np.full((N, L), -1, dtype=np.int32)  # which event sits at each position
    for i, (a, b, u0) in enumerate(zip(days.a.values, days.b.values, days.u0.values)):
        c0 = max(u0, a - CTX)
        seq = [CLS, *prof[i], SEP, *tok[c0:a], SEP]
        n_ctx = len(seq)
        b2 = min(b, a + DAY_MAX)
        seq += list(tok[a:b2])
        ids[i, :len(seq)] = seq
        today[i, n_ctx:len(seq)] = True
        pos_ev[i, n_ctx:len(seq)] = np.arange(a, b2)
        pos_ev[i, 6:6 + (a - c0)] = np.arange(c0, a)
    return ev, days, vocab, ids, today, pos_ev


def model_for(v):
    cfg = BertConfig(vocab_size=v, hidden_size=96, num_hidden_layers=3, num_attention_heads=4, intermediate_size=192,
                     max_position_embeddings=L, hidden_dropout_prob=0.1, attention_probs_dropout_prob=0.1, pad_token_id=PAD)
    return BertForMaskedLM(cfg)


def train(model, ids, maskable, epochs=4, bs=256, lr=1e-3):
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    n = len(ids); steps = epochs * (n // bs); sched = torch.optim.lr_scheduler.OneCycleLR(opt, lr, total_steps=steps)
    X = torch.from_numpy(ids.astype(np.int64)); M = torch.from_numpy(maskable)
    centre = None; step = 0; t0 = time.time()
    model.train()
    for ep in range(epochs):
        perm = torch.randperm(n)
        tot = totv = 0.0
        for k in range(n // bs):
            b = perm[k * bs:(k + 1) * bs]
            x = X[b].clone(); m = M[b]
            pick = (torch.rand(x.shape) < 0.3) & m
            none = ~pick.any(1)                                  # every sequence masks at least one event
            if none.any():
                first = m[none].float().multinomial(1).squeeze(1)
                pick[none.nonzero().squeeze(1), first] = True
            y = torch.where(pick, x, torch.full_like(x, -100))
            x[pick] = MASK
            out = model(input_ids=x, attention_mask=(x != PAD).long(), labels=y, output_hidden_states=True)
            h = out.hidden_states[-1][:, 0]
            loss = out.loss
            if centre is not None:                               # VHM: keep normal sequences close to one centre
                vhm = ((h - centre) ** 2).sum(1).mean()
                loss = loss + ALPHA * vhm; totv += float(vhm)
            opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step(); sched.step()
            tot += float(out.loss); step += 1
        if centre is None:                                       # the centre is fixed after the first epoch, as in LogBERT
            centre = embed(model, ids[:20000]).mean(0)
            model.train()
        print(f"epoch {ep + 1}/{epochs}  masked-key loss {tot / (n // bs):.3f}  hypersphere {totv / (n // bs):.3f}  {time.time() - t0:.0f}s", flush=True)
    return centre


@torch.no_grad()
def embed(model, ids, bs=2048):
    model.eval(); out = []
    for i in range(0, len(ids), bs):
        x = torch.from_numpy(ids[i:i + bs].astype(np.int64))
        out.append(model.bert(input_ids=x, attention_mask=(x != PAD).long()).last_hidden_state[:, 0])
    return torch.cat(out)


@torch.no_grad()
def score(model, ids, today, centre, passes=3, bs=2048):
    """Mask each of today's events once (in `passes` disjoint groups) and ask the model for it."""
    model.eval()
    n = len(ids)
    nll = np.zeros((n, L), dtype=np.float32); miss = np.zeros((n, L), dtype=bool)
    order = np.cumsum(today, 1) - 1
    for p in range(passes):
        pick_all = today & (order % passes == p)
        rows = np.flatnonzero(pick_all.any(1))
        for i in range(0, len(rows), bs):
            r = rows[i:i + bs]
            x = torch.from_numpy(ids[r].astype(np.int64)); pick = torch.from_numpy(pick_all[r])
            true = x[pick]
            x = x.clone(); x[pick] = MASK
            logp = F.log_softmax(model(input_ids=x, attention_mask=(x != PAD).long()).logits[pick], -1)
            t = logp.gather(1, true[:, None]).squeeze(1)
            rank = (logp > t[:, None]).sum(1)
            rr, cc = np.nonzero(pick_all[r])
            nll[r[rr], cc] = -t.numpy(); miss[r[rr], cc] = (rank >= G).numpy()
    dist = ((embed(model, ids) - centre) ** 2).sum(1).numpy()
    return nll, miss, dist


def main():
    t0 = time.time()
    ev, days, vocab, ids, today, pos_ev = build()
    print(f"{len(days):,} user-day sequences, vocabulary {len(vocab)}, built in {time.time() - t0:.0f}s", flush=True)
    tr = (days.day < TRAIN_END).values
    model = model_for(len(vocab))
    print(f"model: {sum(p.numel() for p in model.parameters()) / 1e6:.2f}M parameters; training on {tr.sum():,} sequences", flush=True)
    maskable = (ids > MASK) & (np.arange(L)[None, :] >= 6)          # history and today's events; not the profile
    t1 = time.time()
    centre = train(model, ids[tr], maskable[tr])
    train_s = time.time() - t1
    t1 = time.time()
    nll, miss, dist = score(model, ids, today, centre)
    score_s = time.time() - t1
    n_today = today.sum(1)
    days["lb_nll_sum"] = nll.sum(1); days["lb_nll_mean"] = nll.sum(1) / np.maximum(n_today, 1); days["lb_nll_max"] = nll.max(1)
    days["lb_miss"] = miss.sum(1); days["lb_dist"] = dist
    print(f"trained in {train_s:.0f}s, scored {len(days):,} sequences in {score_s:.0f}s ({len(days) / score_s:.0f}/s)", flush=True)

    res = {"train_seconds": round(train_s), "score_seconds": round(score_s), "parameters": sum(p.numel() for p in model.parameters()),
           "sequences": int(len(days)), "train_sequences": int(tr.sum())}
    for k in ("lb_nll_sum", "lb_nll_mean", "lb_nll_max", "lb_miss", "lb_dist"):
        res[k] = evaluate(days, k, k)
    # LogBERT + the feature baseline: average of the two rankings
    ud = pd.read_parquet(os.path.join(P, "user_days.parquet"))
    days = days.merge(ud[["user", "day", "zscore", "iforest"]], on=["user", "day"], how="left")
    for a, b, name in (("lb_nll_sum", "zscore", "combined"), ("lb_nll_sum", "iforest", "lb+iforest")):
        days[name] = days[a].rank(pct=True) + days[b].rank(pct=True)
        res[name] = evaluate(days, name, name)
    json.dump(res, open(os.path.join(P, "results_logbert.json"), "w"), indent=1)

    # per-event surprise, for the "why" in the review screen
    e_nll = np.zeros(len(ev), dtype=np.float32)
    m = today & (pos_ev >= 0)
    e_nll[pos_ev[m]] = nll[m]
    ev["surprise"] = e_nll
    ev[["id", "surprise"]].to_parquet(os.path.join(P, "event_surprise.parquet"))
    days.drop(columns=["a", "b", "u0"]).to_parquet(os.path.join(P, "user_days_logbert.parquet"))
    torch.save({"state": model.state_dict(), "vocab": vocab, "centre": centre}, os.path.join(P, "logbert.pt"))


if __name__ == "__main__":
    main()
