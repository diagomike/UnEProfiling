"""Build demo/behaviour-watch.html: the real console, frozen.

The page is the same watch.css and watch.js the live tool serves. Only its `api()` function
is swapped (demo/snapshot_api.js) for one that answers from data embedded in the page: a
month of the scored CERT r4.2 test watch, taken through the same server functions the live
console calls. So what a viewer sees is what an analyst sees, without Python, logs or a
server. Decisions, revealed names and the access log work for the session and are not
saved; re-scoring does not run.

Everyone in it is one of CERT's simulated employees.

    python build_demo.py [first day, default 2010-06-28] [days, default 30]
"""
import json
import os
import re
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from watch import server  # noqa: E402

WS = os.path.join(HERE, "workspaces", "cert-r42")
START = sys.argv[1] if len(sys.argv) > 1 else "2010-06-28"
N_DAYS = int(sys.argv[2]) if len(sys.argv) > 2 else 30
PROFILES = 70                      # people whose full profile is carried


def main():
    server.load(WS)
    W, ws = server.W, server.W["ws"]
    days = [d for d in sorted(W["day_index"]) if d >= pd.Timestamp(START)][:N_DAYS]
    ds = [str(d.date()) for d in days]
    st = server.state()
    keep = [i for i, d in enumerate(st["days"]) if d in ds]
    st.update(days=ds, alerts=[st["alerts"][i] for i in keep], known=[st["known"][i] for i in keep], folder="(snapshot)",
              analysts=["Analyst 1", "Analyst 2", "Supervisor"])
    out = {"state": st, "queue": {}, "alert": {}, "machines": {}, "machine": {}, "person": {}, "names": {},
           "mem": {"shown": {}, "last": {}, "open": {}, "decisions": [], "audit": [], "expected": []}}
    codes = []
    for d in ds:
        q = server.queue(d, key=1)
        out["queue"][d] = q
        for r in q["rows"] + q.get("missed", []):
            out["alert"][f"{r['code']}|{d}"] = server.alert(r["code"], d, key=1)
            codes.append(r["code"])
        m = server.machines(d)
        m["rows"] = m["rows"][:8]
        out["machines"][d] = m
        for r in m["rows"]:
            out["machine"][f"{r['host']}|{d}"] = server.machine(r["host"], d)
        print(d, len(q["rows"]), "alerts,", len(q.get("missed", [])), "missed,", len(m["rows"]), "machines", flush=True)
    out["people"] = server.people(ds[-1], window=N_DAYS)
    seen = pd.Series(codes).value_counts()
    want = list(dict.fromkeys([r["code"] for r in out["people"]["rows"][:PROFILES // 2]] + list(seen.index)))[:PROFILES]
    for c in want:
        p = server.person(c)
        p["alerts"] = [a for a in p["alerts"] if a["day"] in out["queue"]]
        out["person"][c] = p
    every = {r["code"] for r in out["people"]["rows"]} | set(codes) | {e["who"]["code"] for m in out["machine"].values() for e in m["events"]} \
        | {r["owner"]["code"] for m in out["machines"].values() for r in m["rows"] if r.get("owner")}
    for c in every:                                             # what "Show name" reveals: CERT's simulated employees
        a = W["codes"][c]
        p = server._person(a, {a})
        out["names"][c] = {"name": p["name"], "account": p["account"], "manager": p.get("manager", "")}
    out["measured"] = server.measured()
    s = server.setup()
    out["setup"] = {"sources": [{**x, "path": "CERT r4.2 (five logs)"} for x in s["sources"]], "months": s["months"], "meta": s["meta"],
                    "folder": "Snapshot of the CERT r4.2 test watch"}
    if os.path.exists(ws.p("audit.jsonl")):                     # building the snapshot opened every record; that is not an analyst's access
        os.remove(ws.p("audit.jsonl"))

    web = os.path.join(HERE, "watch", "web")
    css = open(os.path.join(web, "watch.css"), encoding="utf-8").read()
    js = open(os.path.join(web, "watch.js"), encoding="utf-8").read()
    body = re.search(r"<body>(.*)<script src", open(os.path.join(web, "index.html"), encoding="utf-8").read(), re.S).group(1)
    api = open(os.path.join(HERE, "demo", "snapshot_api.js"), encoding="utf-8").read()
    a, b = js.index("async function api(path, body) {"), js.index("const qs = o =>")
    js = js[:a] + api + "\n" + js[b:]
    js = js.replace("me: store.get('bw_me') || '',", "me: store.get('bw_me') || 'Analyst 1',")
    js = js.replace('<a class="btn" href="/api/export/decisions.csv">Download decisions (CSV)</a><a class="btn" href="/api/export/alerts.csv">Download all alerts (CSV)</a>',
                    '<span class="mute small">The installed tool exports decisions and alerts as CSV here.</span>')
    assert "/api/export" not in js and "fetch(" not in js, "the snapshot must not call a server"
    note = (f'<div id="snap">Snapshot of the console on the CERT r4.2 test data, {days[0].strftime("%d %b")} to {days[-1].strftime("%d %b %Y")}. '
            'Everyone here is simulated. Turn on <b>Answer key</b> to see which alerts were scripted insiders. Decisions you take are not saved.</div>')
    css += "\n#snap{flex:none;padding:5px 16px;background:var(--amber-bg);color:var(--ink);font-size:12px;border-bottom:1px solid var(--line)}\n"
    data = json.dumps(out, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")
    # the charset line matters when the file is opened straight from disk; a published artifact declares it too
    page = f"<title>Behaviour Watch</title>\n<meta charset=\"utf-8\">\n<style>\n{css}</style>\n{note}\n{body}\n<script>\nconst DEMO = {data};\n</script>\n<script>\n{js}\n</script>\n"
    open(os.path.join(HERE, "demo", "behaviour-watch.html"), "w", encoding="utf-8").write(page)
    print(f"demo/behaviour-watch.html  {len(page) / 1e6:.1f} MB: {len(ds)} days, {len(out['alert'])} alert days, {len(out['person'])} profiles, "
          f"{len(out['machine'])} machine days")


if __name__ == "__main__":
    main()
