"""The sequence detector: LogBERT (Guo, Yuan & Wu, 2021), moved from system logs to people.

LogBERT learns what normal log sequences look like with two self-supervised tasks and no
labels: predict masked log keys, and pull every normal sequence's summary vector towards
one centre. A sequence whose masked keys the model cannot guess is anomalous.

A system-log session is long and anonymous. A person's day is short and only means
something relative to that person, so each sequence here is

    [CLS] role, habits (USB / after-hours / other machines) [SEP]
          the person's last events before today [SEP] today's events

and only today's events are scored. Each event is a token saying what, when in the day
and on whose machine: "logon|night|own", "usb_connect|work|other", "mail:out+att|work",
"web:Job search|work". Ordinary web visits carry no token (they would drown everything
else); visits to listed or rarely used sites do. Runs of the same token are shortened.

The model is small (about 0.3 million parameters) and trains on a laptop CPU.
"""
from __future__ import annotations

import os
import time

import numpy as np
import pandas as pd

CTX, DAY_MAX = 24, 48
L = 6 + CTX + 1 + DAY_MAX
PAD, CLS, SEP, MASK = 0, 1, 2, 3
ALPHA = 0.1                      # weight of the hypersphere term
ARCHIVES = {"zip", "rar", "7z", "tar", "gz"}


def tokens(ws, hab, log=print):
    """Every event worth a token: actor, ts, day, tok."""
    from .features import PROGRAMS, _off
    hours = ws.cfg["hours"]
    listed = {d.lower(): cat for cat, ds in ws.cfg["sites"].items() for d in ds}
    n_people = len(hab["first_seen"])
    rare = set(hab["site_users"][hab["site_users"] <= max(2, 0.01 * n_people)].index.astype(str)) if "site_users" in hab else set()
    known = set(hab["site_users"].index.astype(str)) if "site_users" in hab else set()
    out = []
    for m in ws.months():
        e = ws.read_events(m, columns=["ts", "actor", "host", "action", "object", "amount", "external"])
        for c in ("actor", "host", "action"):
            e[c] = e[c].astype(str)
        obj = e.object.astype(object)
        a = e.action.copy()
        web = a.str.startswith("web_")
        cat = obj.map(listed).where(web)
        is_rare = web & cat.isna() & (obj.isin(rare) | ~obj.isin(known))
        keep = ~web | cat.notna() | is_rare
        a = a.where(~(web & cat.notna()), "web:" + cat.fillna("")).where(~is_rare, "web:rare")
        fil = e.action == "file_to_usb"
        a = a.where(~fil, np.where(obj.isin(PROGRAMS), "file:program", np.where(obj.isin(ARCHIVES), "file:archive", "file:document")))
        em = e.action == "email_send"
        a = a.where(~em, np.where(obj.astype(str).str.startswith("from-personal"), "mail:personal",
                                  np.where(~e.external, "mail:in", np.where(e.amount > 0, "mail:out+att", "mail:out"))))
        h = e.ts.dt.hour
        part = np.select([(h >= hours["start"]) & (h < hours["end"]), (h >= hours["start"] - 2) & (h < hours["start"]),
                          (h >= hours["end"]) & (h < hours["end"] + 3)], ["work", "early", "evening"], "night")
        home = e.actor.map(hab["home"])
        where = np.where(e.host == "", "", np.where(e.host == home, "|own", np.where(e.host.isin(hab["shared"]), "|shared", "|other")))
        tok = a + "|" + part + where + np.where(e.ts.dt.dayofweek.isin(hours["weekend"]), "|we", "")
        t = pd.DataFrame({"actor": e.actor, "ts": e.ts, "tok": tok})[keep.values].sort_values(["actor", "ts"], kind="stable")
        t["day"] = t.ts.dt.normalize()
        g = t.groupby(["actor", "day"], sort=False).tok
        t = t[~((t.tok == g.shift(1)) & (t.tok == g.shift(2)))]          # a run of the same thing keeps its first two
        out.append(t)
    t = pd.concat(out, ignore_index=True).sort_values(["actor", "ts"], kind="stable").reset_index(drop=True)
    log(f"  sequence: {len(t):,} tokens from {t.tok.nunique()} kinds")
    return t


def _habit(x, lo):
    return np.where(pd.isna(x), "unk", np.where(x <= 0, "none", np.where(x < lo, "low", "high")))


def build(t, days, vocab=None):
    """Token table + days table -> fixed-width id matrix, one row per person-day that has tokens."""
    roles = sorted(days.role.dropna().unique())
    if vocab is None:
        vocab = ["[PAD]", "[CLS]", "[SEP]", "[MASK]", "[UNK]"] + sorted(t.tok.unique()) + [f"role={r}" for r in roles] + ["role=?"] + \
                [f"{k}={v}" for k in ("usb", "afterhours", "othermachine") for v in ("unk", "none", "low", "high")]
    idx = {w: i for i, w in enumerate(vocab)}
    tok = t.tok.map(idx).fillna(idx["[UNK]"]).values.astype(np.int16)
    key = t.actor + "|" + t.day.astype(str)
    start = np.flatnonzero(np.r_[True, key.values[1:] != key.values[:-1]])
    end = np.r_[start[1:], len(t)]
    u0 = pd.Series(np.arange(len(t))).groupby(t.actor.values).transform("min").values
    S = pd.DataFrame({"actor": t.actor.values[start], "day": t.day.values[start], "a": start, "b": end, "u0": u0[start]})
    base = [c for c in ("usb_base", "off_logons_base", "other_logons_base") if c in days]
    S = S.merge(days[["actor", "day", "role"] + base], on=["actor", "day"], how="left")
    col = lambda c: S[c] if c in S else pd.Series(np.nan, index=S.index)
    prof = np.stack([S.role.map(lambda r: idx.get(f"role={r}", idx["role=?"])).values,
                     np.array([idx[f"usb={h}"] for h in _habit(col("usb_base"), 0.5)]),
                     np.array([idx[f"afterhours={h}"] for h in _habit(col("off_logons_base"), 0.2)]),
                     np.array([idx[f"othermachine={h}"] for h in _habit(col("other_logons_base"), 0.2)])], 1)
    N = len(S)
    ids = np.zeros((N, L), dtype=np.int16)
    today = np.zeros((N, L), dtype=bool)
    pos = np.full((N, L), -1, dtype=np.int32)                  # which token-table row sits at each position
    for i, (a, b, s0) in enumerate(zip(S.a.values, S.b.values, S.u0.values)):
        c0 = max(s0, a - CTX)
        seq = [CLS, *prof[i], SEP, *tok[c0:a], SEP]
        n = len(seq)
        b2 = min(b, a + DAY_MAX)
        ids[i, :n] = seq
        ids[i, n:n + b2 - a] = tok[a:b2]
        today[i, n:n + b2 - a] = True
        pos[i, n:n + b2 - a] = np.arange(a, b2)
    return S[["actor", "day"]], vocab, ids, today, pos


def _model(v):
    from transformers import BertConfig, BertForMaskedLM
    return BertForMaskedLM(BertConfig(vocab_size=v, hidden_size=96, num_hidden_layers=3, num_attention_heads=4, intermediate_size=192,
                                      max_position_embeddings=L, hidden_dropout_prob=0.1, attention_probs_dropout_prob=0.1, pad_token_id=PAD))


def _batches(ids, bs, shuffle):
    """Batches of similar length, each cut to its longest row: most days are short, so this halves the work."""
    n = (ids != PAD).sum(1)
    order = np.random.permutation(len(ids)) if shuffle else np.argsort(n, kind="stable")
    if shuffle:
        order = np.concatenate([c[np.argsort(n[c], kind="stable")] for c in np.array_split(order, max(1, len(order) // (bs * 40)))])
    groups = [order[i:i + bs] for i in range(0, len(order), bs)]
    if shuffle:
        np.random.shuffle(groups)
    for g in groups:
        yield g, int(n[g].max())


def train(ids, today, epochs=3, bs=256, lr=1e-3, log=print):
    import torch
    torch.manual_seed(0); np.random.seed(0)
    torch.set_num_threads(min(16, os.cpu_count() or 4))
    model = _model(int(ids.max()) + 40)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    steps = epochs * (len(ids) // bs + 1)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, lr, total_steps=steps)
    maskable = (ids > 4) & (np.arange(L)[None, :] >= 6)          # history and today's events, never the profile
    centre, t0 = None, time.time()
    for ep in range(epochs):
        model.train(); tot = k = 0
        for g, width in _batches(ids, bs, True):
            x = torch.from_numpy(ids[g, :width].astype(np.int64)); m = torch.from_numpy(maskable[g, :width])
            pick = (torch.rand(x.shape) < 0.3) & m
            none = ~pick.any(1) & m.any(1)                       # every sequence masks at least one event
            if none.any():
                pick[none.nonzero().squeeze(1), m[none].float().multinomial(1).squeeze(1)] = True
            if not pick.any():
                continue
            y = torch.where(pick, x, torch.full_like(x, -100))
            x = x.clone(); x[pick] = MASK
            out = model(input_ids=x, attention_mask=(x != PAD).long(), labels=y, output_hidden_states=True)
            loss = out.loss
            if centre is not None:                               # keep normal sequences close to one centre
                loss = loss + ALPHA * ((out.hidden_states[-1][:, 0] - centre) ** 2).sum(1).mean()
            opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
            if sched.last_epoch < steps - 1:
                sched.step()
            tot += float(out.loss.detach()); k += 1
        if centre is None:                                       # fixed after the first epoch, as in LogBERT
            centre = _embed(model, ids[:20000]).mean(0)
        log(f"  sequence: epoch {ep + 1}/{epochs}  masked-key loss {tot / max(k, 1):.3f}  {time.time() - t0:.0f}s")
    return model, centre


def _embed(model, ids, bs=2048):
    import torch
    model.eval(); out = []
    with torch.no_grad():
        for g, width in _batches(ids, bs, False):
            x = torch.from_numpy(ids[g, :width].astype(np.int64))
            out.append((g, model.bert(input_ids=x, attention_mask=(x != PAD).long()).last_hidden_state[:, 0]))
    emb = torch.zeros(len(ids), out[0][1].shape[1])
    for g, h in out:
        emb[g] = h
    return emb


def score(model, ids, today, passes=3, bs=2048):
    """Mask each of today's events once (in `passes` disjoint groups) and ask the model for it.
    Returns the surprise (negative log-likelihood) at every position."""
    import torch
    import torch.nn.functional as F
    model.eval()
    nll = np.zeros(ids.shape, dtype=np.float32)
    order = np.cumsum(today, 1) - 1
    with torch.no_grad():
        for p in range(passes):
            pick_all = today & (order % passes == p)
            rows = np.flatnonzero(pick_all.any(1))
            for g, width in _batches(ids[rows], bs, False):
                r = rows[g]
                x = torch.from_numpy(ids[r, :width].astype(np.int64)); pick = torch.from_numpy(pick_all[r, :width])
                true = x[pick]
                x = x.clone(); x[pick] = MASK
                logp = F.log_softmax(model(input_ids=x, attention_mask=(x != PAD).long()).logits[pick], -1)
                rr, cc = np.nonzero(pick_all[r, :width])
                nll[r[rr], cc] = -logp.gather(1, true[:, None]).squeeze(1).numpy()
    return nll


def run(ws, days, hab, retrain=False, log=print):
    """Train (or load) the model and score every person-day. Returns days with `seq` added, and
    writes model/surprise.parquet: the surprise of each scored event, for the console's timeline."""
    import torch
    t = tokens(ws, hab, log)
    path = ws.p("model", "logbert.pt")
    saved = torch.load(path, weights_only=False) if os.path.exists(path) and not retrain else None
    S, vocab, ids, today, pos = build(t, days, saved["vocab"] if saved else None)
    learn_until = pd.Timestamp(ws.cfg["learn_until"]) if ws.cfg.get("learn_until") else S.day.quantile(0.4)
    if saved:
        model = _model(saved["size"]); model.load_state_dict(saved["state"])
        log(f"  sequence: loaded the model trained {saved.get('trained', '?')}")
    else:
        tr = np.flatnonzero((S.day < learn_until).values)
        if len(tr) > 120_000:
            tr = np.sort(np.random.default_rng(0).choice(tr, 120_000, replace=False))
        log(f"  sequence: training on {len(tr):,} of {len(S):,} person-days, vocabulary {len(vocab)}")
        model, centre = train(ids[tr], today[tr], log=log)
        os.makedirs(ws.p("model"), exist_ok=True)
        torch.save({"state": model.state_dict(), "vocab": vocab, "size": model.config.vocab_size, "centre": centre,
                    "trained": time.strftime("%Y-%m-%d %H:%M"), "learn_until": str(learn_until.date())}, path)
    t0 = time.time()
    nll = score(model, ids, today)
    # A day's score is its three most surprising events. Their sum over the whole day grows with how much
    # mail and browsing there was, which buried the signal (attempts/v2_sequence_choices.py).
    S = S.assign(seq=np.sort(nll, 1)[:, -3:].sum(1), seq_sum=nll.sum(1), seq_n=today.sum(1))
    log(f"  sequence: scored {len(S):,} person-days in {time.time() - t0:.0f}s")
    m = today & (pos >= 0)
    sur = np.zeros(len(t), dtype=np.float32); sur[pos[m]] = nll[m]
    t.assign(surprise=sur)[["actor", "ts", "tok", "surprise"]].to_parquet(ws.p("model", "surprise.parquet"), index=False, row_group_size=50_000)
    days = days.drop(columns=[c for c in ("seq", "seq_sum", "seq_max", "seq_n") if c in days]).merge(S, on=["actor", "day"], how="left")
    for c in ("seq", "seq_sum", "seq_n"):
        days[c] = days[c].fillna(0).astype("float32")
    return days
