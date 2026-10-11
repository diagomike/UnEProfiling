"""Behaviour Watch: the analyst console.

One page, served from this computer. It reads a watch folder (workspace.py) that the batch
side (pipeline.py) has scored, and shows:

    Queue      each day's alerts with their reasons; an analyst dismisses, watches or escalates
    People     who has been raising alerts lately, and what is normal for each person
    Machines   computers behaving unlike themselves
    Cases      everything that was escalated or is being watched
    Measured   how the detectors do against known incidents, when the watch has any
    Setup      log sources, expected behaviour, analysts, thresholds, and the access log

Two things are built in because this is monitoring of employees. People appear as codes
(P-3FA2C1) until an analyst gives a reason to see a name, and every opened record and every
revealed name is written to audit.jsonl with who, when and why.

    python -m watch serve <folder>              on this computer only
    python -m watch serve <folder> --lan --password WORD
"""
from __future__ import annotations

import base64
import os
import secrets
import socket
import threading
import time

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import detect, pipeline
from .events import ACTIONS
from .features import COUNTS, HOST_COUNTS
from .workspace import Workspace, read_json

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="Behaviour Watch")
GATE = {"password": ""}
W: dict = {}                                 # the open watch: ws, days, hosts, meta, ...
JOB = {"running": False, "log": [], "error": None}
STATES = ("new", "watching", "escalated", "confirmed", "dismissed")


# ---------------------------------------------------------------- loading
def load(folder=None):
    ws = Workspace(folder) if folder else W["ws"]
    ws.reload()
    if not os.path.exists(ws.p("days.parquet")):
        W.clear(); W.update(ws=ws, days=None, meta={}, counts=[])
        return
    d = pd.read_parquet(ws.p("days.parquet"))
    meta = read_json(ws.p("scored.json"), {})
    counts = meta.get("counts") or [c[:-4] for c in d.columns if c.endswith("_dev")]
    learned, until = pipeline.learned_mask(ws, d)
    d = detect.rescore(d, counts, learned, ws.cfg.get("expected"), context=ws.cfg["context_only"], sequence_weight=ws.cfg["sequence_weight"])
    hd = pd.read_parquet(ws.p("hosts.parquet")) if os.path.exists(ws.p("hosts.parquet")) else None
    if hd is not None and len(hd):
        hd = detect.rescore(hd, list(HOST_COUNTS), (hd.day < until).values, key="host")
    who = ws.directory()
    codes = {ws.code(a): a for a in d.actor.unique()}
    W.clear()
    W.update(ws=ws, days=d, hosts=hd, meta=meta, counts=counts, learned=learned, who=who, codes=codes,
             code_of={a: c for c, a in codes.items()}, by_actor=d.groupby("actor", sort=False).indices,
             day_index=d.groupby("day", sort=True).indices, labels=_labels(ws),
             owner=dict(hd.drop_duplicates("host")[["host", "owner"]].values) if hd is not None and "owner" in hd else {})
    _decisions()


def _labels(ws):
    f = ws.p("labels.parquet")
    if not os.path.exists(f):
        return set()
    L = pd.read_parquet(f)
    return set(zip(L.actor, L.ts.dt.strftime("%Y-%m-%d %H:%M:%S")))


def _decisions():
    """The latest decision per (person, day), and per person."""
    last, person = {}, {}
    for r in W["ws"].decisions():
        last[(r["actor"], r.get("day"))] = r
        if r.get("state") in ("watching", "escalated", "confirmed"):
            person[r["actor"]] = r
        elif r.get("state") in ("dismissed", "closed") and person.get(r["actor"], {}).get("day") == r.get("day"):
            person.pop(r["actor"], None)
    W["last"], W["open"] = last, person


def need():
    if not W.get("ws"):
        raise HTTPException(409, "No watch is open")
    if W.get("days") is None:
        raise HTTPException(409, "This watch has not been scored yet. Use Setup, Read new logs.")
    return W


def _revealed(analyst):
    """People whose names this analyst has revealed today."""
    today = time.strftime("%Y-%m-%d")
    return {r["actor"] for r in W["ws"].audits() if r.get("action") == "reveal" and r.get("analyst") == analyst and r["at"][:10] == today}


def _person(actor, shown):
    """How a person appears: a code, plus the name when this analyst has revealed it (or the watch does not hide names)."""
    w = W["who"]
    r = w.loc[actor] if actor in w.index else None
    open_ = not W["ws"].cfg["pseudonyms"] or actor in shown
    out = {"code": W["code_of"].get(actor, W["ws"].code(actor)), "role": (r.role if r is not None else "") or "", "department": r.department if r is not None else "",
           "left": r.left if r is not None else "", "named": open_}
    if open_:
        out.update(name=(r["name"] if r is not None else "") or actor, account=actor, manager=r.manager if r is not None else "")
    return out


def _actor(code):
    a = W["codes"].get(code)
    if a is None:
        raise HTTPException(404, "No such person in this watch")
    return a


def _day(s):
    try:
        return pd.Timestamp(s).normalize()
    except Exception:
        raise HTTPException(400, "Bad date")


def _thr():
    return float(W["ws"].cfg["alert_percentile"])


def _state(actor, day):
    r = W["last"].get((actor, str(day.date())))
    return r["state"] if r else "new"


# ---------------------------------------------------------------- access
@app.middleware("http")
async def gate(request: Request, call_next):
    """With --password, anyone not sitting at this computer gives the password first (the browser asks once)."""
    if GATE["password"] and not (request.client and request.client.host in ("127.0.0.1", "::1")):
        given = ""
        try:
            given = base64.b64decode(request.headers.get("authorization", "")[6:]).decode().split(":", 1)[1]
        except Exception:
            pass
        if not secrets.compare_digest(given.encode(), GATE["password"].encode()):
            return Response("Behaviour Watch: a password is needed.", 401, headers={"WWW-Authenticate": 'Basic realm="Behaviour Watch", charset="UTF-8"'})
    return await call_next(request)


# ---------------------------------------------------------------- state
@app.get("/api/state")
def state():
    if not W.get("ws"):
        return {"open": False}
    ws, cfg = W["ws"], W["ws"].cfg
    out = {"open": True, "name": cfg["name"], "folder": ws.dir, "analysts": cfg["analysts"], "pseudonyms": cfg["pseudonyms"],
           "dismiss_reasons": cfg["dismiss_reasons"], "reveal_reasons": cfg["reveal_reasons"], "alert_percentile": cfg["alert_percentile"],
           "scored": W.get("days") is not None, "meta": W.get("meta", {}), "job": {"running": JOB["running"]}}
    if W.get("days") is not None:
        d = W["days"]
        a = d[d.risk > _thr()].groupby("day").size()
        per_day = d.groupby("day").size()
        strip = pd.DataFrame({"n": per_day, "alerts": a}).fillna(0)
        if W["labels"]:
            strip["bad"] = d[d.bad].groupby("day").size()
        strip = strip.fillna(0).astype(int)
        out.update(days=[str(x.date()) for x in strip.index], alerts=strip.alerts.tolist(), known=strip.bad.tolist() if "bad" in strip else None,
                   has_labels=bool(W["labels"]), roles=sorted(x for x in d.role.unique() if x),
                   counts=[{"key": c, "label": COUNTS[c][0]} for c in W["counts"]]
                   + [{"key": "family:" + f, "label": f"Everything from the {f} log"} for f in sorted({COUNTS[c][1] for c in W["counts"]} - {"any"})], has_hosts=W.get("hosts") is not None,
                   expected=cfg["expected"], hours=cfg["hours"], sites=cfg["sites"])
    return out


# ---------------------------------------------------------------- queue
def _row(r, shown, key_show):
    actor = r["actor"]
    day = r["day"]
    out = {**_person(actor, shown), "day": str(day.date()), "risk": round(float(r["risk"]), 2), "state": _state(actor, day),
           "why": detect.reasons(r, W["counts"], limit=3), "own": round(float(r.get("own_pct", 0)), 1), "seq": round(float(r.get("seq_pct", 0)), 1)}
    if actor in W["open"]:
        out["case"] = W["open"][actor]["state"]
    if key_show and bool(r.get("bad")):
        out["known"] = int(r.get("scenario", 0)) or 1
    return out


@app.get("/api/queue")
def queue(day: str, analyst: str = "", key: int = 0):
    need()
    d, t = W["days"], _day(day)
    idx = W["day_index"].get(t)
    if idx is None:
        return {"day": day, "rows": [], "active": 0}
    x = d.iloc[idx]
    q = x[x.risk > _thr()].sort_values("risk_raw", ascending=False)
    shown = _revealed(analyst)
    rows = [_row(r, shown, key and W["labels"]) for r in q.to_dict("records")]
    out = {"day": day, "active": int(len(x)), "rows": rows}
    if key and W["labels"]:                                         # known incident days the queue missed
        out["missed"] = [_row(r, shown, True) for r in x[x.bad & (x.risk <= _thr())].sort_values("risk", ascending=False).to_dict("records")]
    return out


def _timeline(actor, day, key_show):
    ws = W["ws"]
    e = ws.read_events(day.strftime("%Y-%m"), actor=actor, as_category=())
    e = e[e.ts.dt.normalize() == day].sort_values("ts", kind="stable")
    sur = {}
    f = ws.p("model", "surprise.parquet")
    if os.path.exists(f):
        s = pq.read_table(f, filters=[("actor", "==", actor), ("ts", ">=", day), ("ts", "<", day + pd.Timedelta(days=1))]).to_pandas()
        for t, v in zip(s.ts, s.surprise):
            sur[t] = max(sur.get(t, 0.0), float(v))
    owner = W["owner"]
    listed = {x.lower(): cat for cat, xs in ws.cfg["sites"].items() for x in xs}
    web = e.action.str.startswith("web_")
    fresh = set()                                                   # sites this person had not visited in the 45 days before
    if web.any():
        since = day - pd.Timedelta(days=45)
        months = sorted({since.strftime("%Y-%m"), (day - pd.Timedelta(days=1)).strftime("%Y-%m")} & set(ws.months()))
        before = [ws.read_events(m, columns=["ts", "action", "object"], actor=actor, as_category=()) for m in months]
        before = pd.concat(before) if before else e.iloc[:0]
        before = before[(before.ts >= since) & (before.ts < day) & before.action.str.startswith("web_")]
        if len(before):
            fresh = set(e.object[web]) - set(before.object)
    out, plain_web, plain_sites = [], 0, set()
    for r in e.itertuples(index=False):
        ts = r.ts.strftime("%Y-%m-%d %H:%M:%S")
        s = sur.get(r.ts, 0.0)
        bad = bool(key_show and (actor, ts) in W["labels"])
        if r.action.startswith("web_") and not bad and r.object not in listed and r.object not in fresh and s <= 0:
            plain_web += 1; plain_sites.add(r.object)               # ordinary browsing is summed up, not listed
            continue
        where = "" if not r.host else "own" if owner.get(r.host) == actor else "other" if owner.get(r.host) else "shared"
        detail = r.object
        if r.action == "email_send":
            doms = [x for x in r.object.split(";") if x and x != "from-personal"]
            detail = ("to " + ", ".join(doms) if doms else "inside the organisation") + (f", {int(r.amount)} attachment{'s' if r.amount > 1 else ''}" if r.amount else "") \
                     + (" (from a personal address)" if r.object.startswith("from-personal") else "")
        elif r.action.startswith("web_"):
            notes = ([listed[r.object]] if r.object in listed else []) + (["new for them"] if r.object in fresh else [])
            detail = r.object + (f" ({', '.join(notes)})" if notes else "")
        elif r.action == "file_to_usb":
            detail = f".{r.object} file" if r.object else ""
        out.append({"t": r.ts.strftime("%H:%M"), "a": ACTIONS.get(r.action, r.action), "k": r.action, "d": detail, "h": r.host, "w": where,
                    "s": round(s, 1), **({"known": True} if bad else {})})
    return out, plain_web, len(plain_sites)


@app.get("/api/alert")
def alert(code: str, day: str, analyst: str = "", key: int = 0):
    need()
    actor, t = _actor(code), _day(day)
    d = W["days"]
    mine = d.iloc[W["by_actor"][actor]]
    row = mine[mine.day == t]
    if not len(row):
        raise HTTPException(404, "No activity for this person on this day")
    r = row.iloc[0].to_dict()
    shown = _revealed(analyst)
    counts = []
    for c in W["counts"]:
        base = r.get(f"{c}_base")
        if r[c] > 0 or (base is not None and not pd.isna(base) and base >= 0.05):
            counts.append({"label": COUNTS[c][0], "today": round(float(r[c]), 1), "usual": None if base is None or pd.isna(base) else round(float(base), 2),
                           "role": round(float(r.get(f"{c}_role", 0)), 2), "rare": round(float(r.get(f"{c}_rare", 0)), 1), "key": c})
    counts.sort(key=lambda x: -x["rare"])
    tl, plain, sites = _timeline(actor, t, key and W["labels"])
    near = mine[(mine.day >= t - pd.Timedelta(days=90)) & (mine.day <= t + pd.Timedelta(days=14))]
    spark = [[str(a.date()), round(float(b), 1)] + ([1] if key and W["labels"] and k else []) for a, b, k in zip(near.day, near.risk, near.bad)]
    hist = [x for x in W["ws"].decisions() if x["actor"] == actor][-12:]
    for h in hist:
        h.pop("actor", None)
    W["ws"].audit(analyst=analyst, action="open", actor=actor, code=code, day=day)
    return {**_row(r, shown, key and W["labels"]), "why": detect.reasons(r, W["counts"], limit=6), "counts": counts, "timeline": tl,
            "plain_web": plain, "plain_sites": sites, "spark": spark, "history": hist[::-1], "threshold": _thr(),
            "first_hour": round(float(r.get("first_hour", 0)), 1), "last_hour": round(float(r.get("last_hour", 0)), 1)}


# ---------------------------------------------------------------- decisions, names, rules
@app.post("/api/decide")
def decide(b: dict = Body(...)):
    need()
    if b.get("state") not in STATES or not b.get("analyst"):
        raise HTTPException(400, "Choose who you are and what you decided")
    actor = _actor(b["code"])
    W["ws"].decide(actor=actor, code=b["code"], day=b["day"], state=b["state"], reason=b.get("reason", ""), note=(b.get("note") or "")[:2000], analyst=b["analyst"])
    _decisions()
    return {"ok": True, "state": b["state"]}


@app.post("/api/reveal")
def reveal(b: dict = Body(...)):
    need()
    if not b.get("analyst") or not b.get("reason"):
        raise HTTPException(400, "A name is shown only to a named analyst who gives a reason")
    actor = _actor(b["code"])
    W["ws"].audit(analyst=b["analyst"], action="reveal", actor=actor, code=b["code"], reason=b["reason"])
    return _person(actor, {actor})


@app.post("/api/expected")
def expected(b: dict = Body(...)):
    """Add or remove a rule saying some behaviour is normal for a role or a person, then re-score."""
    need()
    ws = W["ws"]
    rules = ws.cfg["expected"]
    if b.get("remove") is not None:
        rules[:] = [r for i, r in enumerate(rules) if i != int(b["remove"])]
    else:
        who = b.get("who", "")
        if who.startswith("code:"):
            who = "actor:" + _actor(who[5:])
        if not who or not (b.get("what") in W["counts"] + ["*"] or str(b.get("what", "")).startswith("family:")):
            raise HTTPException(400, "Choose who and what")
        rules.append({"who": who, "what": b["what"], "by": b.get("analyst", ""), "at": time.strftime("%Y-%m-%d %H:%M"), "note": b.get("note", "")})
    ws.save()
    ws.audit(analyst=b.get("analyst", ""), action="rule", detail=str(b))
    before = int((W["days"].risk > _thr()).sum())
    load()
    return {"ok": True, "alerts_before": before, "alerts_after": int((W["days"].risk > _thr()).sum())}


@app.post("/api/settings")
def settings(b: dict = Body(...)):
    ws = W["ws"]
    for k in ("alert_percentile", "analysts", "pseudonyms", "hours", "sites", "name"):
        if k in b:
            ws.cfg[k] = b[k]
    ws.cfg["alert_percentile"] = float(min(99.99, max(90, float(ws.cfg["alert_percentile"]))))
    ws.save()
    ws.audit(analyst=b.get("analyst", ""), action="settings", detail=",".join(k for k in b if k != "analyst"))
    return {"ok": True}


# ---------------------------------------------------------------- people
@app.get("/api/people")
def people(day: str, window: int = 30, q: str = "", role: str = "", analyst: str = ""):
    need()
    d, t = W["days"], _day(day)
    x = d[(d.day <= t) & (d.day > t - pd.Timedelta(days=window))]
    g = x.assign(alert=x.risk > _thr()).groupby("actor").agg(alerts=("alert", "sum"), peak=("risk", "max"), days=("day", "size"), role=("role", "first"))
    last = x[x.risk > _thr()].groupby("actor").day.max()
    g["last"] = last
    if role:
        g = g[g.role == role]
    shown = _revealed(analyst)
    if q:
        ql = q.lower()
        keep = [a for a in g.index if ql in W["code_of"][a].lower() or ((a in shown or not W["ws"].cfg["pseudonyms"]) and (ql in a.lower() or ql in str(W["who"]["name"].get(a, "")).lower()))]
        g = g.loc[keep]
    g = g.sort_values(["alerts", "peak"], ascending=False).head(150)
    return {"rows": [{**_person(a, shown), "alerts": int(r.alerts), "peak": round(float(r.peak), 1), "active_days": int(r.days),
                      "last": None if pd.isna(r["last"]) else str(r["last"].date()), "case": W["open"].get(a, {}).get("state")} for a, r in g.iterrows()],
            "window": window}


@app.get("/api/person")
def person(code: str, analyst: str = ""):
    need()
    actor = _actor(code)
    ws, d = W["ws"], W["days"]
    mine = d.iloc[W["by_actor"][actor]]
    hours, hosts, kinds = np.zeros(24, dtype=int), {}, {}
    for m in ws.months():
        e = ws.read_events(m, columns=["ts", "host", "action"], actor=actor, as_category=())
        if not len(e):
            continue
        act = e[~e.action.isin(["logoff", "usb_disconnect"])]
        hours += np.bincount(act.ts.dt.hour, minlength=24)
        for h, n in e[e.action == "logon"].host.value_counts().items():
            hosts[h] = hosts.get(h, 0) + int(n)
        for a, n in act.action.value_counts().items():
            kinds[a] = kinds.get(a, 0) + int(n)
    typical = []
    for c in W["counts"]:
        v = mine[c].values
        if v.sum() > 0:
            typical.append({"label": COUNTS[c][0], "median": round(float(np.median(v)), 1), "high": round(float(np.quantile(v, 0.95)), 1),
                            "days": int((v > 0).sum()), "max": round(float(v.max()), 1)})
    series = [[str(a.date()), round(float(b), 1)] for a, b in zip(mine.day, mine.risk)]
    al = mine[mine.risk > _thr()].sort_values("day", ascending=False).head(60)
    shown = _revealed(analyst)
    hist = [x for x in ws.decisions() if x["actor"] == actor]
    for h in hist:
        h.pop("actor", None)
    ws.audit(analyst=analyst, action="profile", actor=actor, code=code)
    return {**_person(actor, shown), "first": str(mine.day.min().date()), "last": str(mine.day.max().date()), "active_days": int(len(mine)),
            "hours": hours.tolist(), "machines": sorted(hosts.items(), key=lambda x: -x[1])[:6],
            "kinds": [[ACTIONS.get(k, k), n] for k, n in sorted(kinds.items(), key=lambda x: -x[1])], "typical": typical, "series": series,
            "alerts": [{"day": str(r["day"].date()), "risk": round(float(r["risk"]), 1), "why": detect.reasons(r, W["counts"], limit=2),
                        "state": _state(actor, r["day"])} for r in al.to_dict("records")],
            "history": hist[::-1], "threshold": _thr(), "case": W["open"].get(actor)}


# ---------------------------------------------------------------- machines
@app.get("/api/machines")
def machines(day: str, analyst: str = ""):
    need()
    hd = W.get("hosts")
    if hd is None:
        return {"rows": []}
    t = _day(day)
    x = hd[(hd.day == t) & (hd.risk > _thr())].sort_values("risk_raw", ascending=False).head(60)
    shown = _revealed(analyst)
    rows = []
    for r in x.to_dict("records"):
        rows.append({"host": r["host"], "risk": round(float(r["risk"]), 2), "why": detect.reasons(r, list(HOST_COUNTS), limit=3),
                     "owner": _person(r["owner"], shown) if r.get("owner") else None,
                     "counts": [{"label": HOST_COUNTS[c], "today": float(r[c]), "usual": None if pd.isna(r.get(f"{c}_base")) else round(float(r[f"{c}_base"]), 2)} for c in HOST_COUNTS if r[c] > 0]})
    return {"rows": rows, "day": day}


@app.get("/api/machine")
def machine(host: str, day: str, analyst: str = ""):
    need()
    t = _day(day)
    e = W["ws"].read_events(t.strftime("%Y-%m"), host=host, as_category=())
    e = e[(e.ts.dt.normalize() == t) & ~e.action.astype(str).str.startswith("web_")].sort_values("ts")
    shown = _revealed(analyst)
    return {"host": host, "events": [{"t": r.ts.strftime("%H:%M"), "a": ACTIONS.get(r.action, r.action), "d": r.object if r.action != "email_send" else "",
                                      "who": _person(r.actor, shown)} for r in e.head(300).itertuples(index=False)]}


# ---------------------------------------------------------------- cases, measured, setup
@app.get("/api/cases")
def cases(analyst: str = ""):
    need()
    shown = _revealed(analyst)
    out = []
    for r in reversed(W["ws"].decisions()):
        out.append({**{k: v for k, v in r.items() if k != "actor"}, "person": _person(r["actor"], shown)})
    return {"rows": out[:400], "open": [{**{k: v for k, v in r.items() if k != "actor"}, "person": _person(a, shown)} for a, r in W["open"].items()]}


@app.get("/api/export/{kind}.csv")
def export(kind: str, start: str = "", end: str = ""):
    """Alerts or decisions as a CSV for a report. People appear as codes; names stay in the console."""
    need()
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    if kind == "decisions":
        w.writerow(["when", "analyst", "person", "alert_day", "state", "reason", "note"])
        for r in W["ws"].decisions():
            w.writerow([r["at"], r.get("analyst", ""), r.get("code", ""), r.get("day", ""), r.get("state", ""), r.get("reason", ""), r.get("note", "")])
    elif kind == "alerts":
        d = W["days"]
        x = d[d.risk > _thr()]
        if start:
            x = x[x.day >= _day(start)]
        if end:
            x = x[x.day <= _day(end)]
        w.writerow(["day", "person", "role", "risk", "state", "reasons"])
        for r in x.sort_values(["day", "risk_raw"], ascending=[True, False]).head(20000).to_dict("records"):
            w.writerow([str(r["day"].date()), W["code_of"][r["actor"]], r["role"], round(float(r["risk"]), 2), _state(r["actor"], r["day"]),
                        " | ".join(detect.reasons(r, W["counts"], limit=3))])
    else:
        raise HTTPException(404, "alerts or decisions")
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{kind}.csv"'})


@app.get("/api/measured")
def measured():
    need()
    return read_json(W["ws"].p("measured.json"), None) or {}


@app.get("/api/setup")
def setup():
    ws = W["ws"]
    seen = read_json(ws.p("events", "_read.json"), {})
    return {"sources": [{**s, "files": len(seen.get(s["name"], {})), "found": os.path.exists(ws.resolve(s["path"]))} for s in ws.cfg["sources"]],
            "months": ws.months(), "audit": [{k: v for k, v in r.items() if k != "actor"} for r in ws.audits()[-200:]][::-1],
            "meta": W.get("meta", {}), "folder": ws.dir, "job": JOB}


@app.post("/api/update")
def update(b: dict = Body(default={})):
    """Read new logs and re-score, in the background."""
    if JOB["running"]:
        raise HTTPException(409, "Already running")
    JOB.update(running=True, log=[], error=None)

    def work():
        try:
            n = W["ws"].ingest(JOB["log"].append)
            JOB["log"].append(f"{n:,} new events")
            if n or b.get("force") or W.get("days") is None:
                d, _, _ = pipeline.score(W["ws"], retrain=bool(b.get("retrain")), log=JOB["log"].append)
                if d.bad.any():
                    pipeline.measure(W["ws"], d, log=JOB["log"].append)
                load()
            JOB["log"].append("done")
        except Exception as e:                                      # shown in Setup
            JOB["error"] = f"{type(e).__name__}: {e}"
        finally:
            JOB["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return {"ok": True}


@app.get("/api/job")
def job():
    return JOB


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "web", "index.html"), headers={"Cache-Control": "no-store"})


app.mount("/web", StaticFiles(directory=os.path.join(HERE, "web")), name="web")


def run(folder=None, port=8770, lan=False, password=""):
    import uvicorn
    if not folder:
        raise SystemExit("Which watch?  python -m watch serve <folder>   (or build the test one first: python -m watch demo)")
    load(folder)
    GATE["password"] = password
    if lan and not password:
        print("  --lan without --password: anyone on the network can open this console.")
    url = f"http://127.0.0.1:{port}"
    print(f"Behaviour Watch: {W['ws'].cfg['name']}\n  {url}" + (f"\n  http://{socket.gethostname()}:{port} from other computers" if lan else ""))
    uvicorn.run(app, host="0.0.0.0" if lan else "127.0.0.1", port=port, log_level="warning")
