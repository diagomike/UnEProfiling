"""End to end on logs that are not CERT: does a new watch, fed Windows Security events it has
never seen, put a planted misuse at the top of that day's queue?

It writes ten weeks of made-up Windows events for a 40-person office (JSON lines in the shape
Winlogbeat and Security-Datasets use), plants one bad night (a clerk logs on at 02:10 to a
colleague's machine and plugs in a USB drive, having done neither before), builds a watch from
nothing with the `windows` adapter, scores it without the sequence model, and checks the queue
through the same HTTP interface the console uses. It also runs the adapters over the real
sample logs in data/samples, when they are there.

    python tests/own_logs_test.py
"""
import datetime as dt
import glob
import json
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from watch import pipeline  # noqa: E402
from watch.adapters import Sshd, Windows  # noqa: E402
from watch.workspace import Workspace  # noqa: E402

random.seed(7)
PEOPLE = [f"user{i:02d}" for i in range(40)]
START = dt.date(2026, 3, 2)                    # a Monday
BAD_WHO, BAD_DAY, VICTIM_PC = "user17", START + dt.timedelta(days=64), "WS-005"


def ev(when, eid, user, pc, **more):
    # the organisation is in Addis Ababa (UTC+3); logs carry UTC
    return json.dumps({"EventID": eid, "Channel": "Security", "@timestamp": (when - dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                       "Hostname": f"{pc}.office.local", "TargetUserName": user, "SubjectUserName": user, **more})


def make_logs(folder):
    os.makedirs(folder)
    lines = []
    for d in range(70):
        day = START + dt.timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for i, u in enumerate(PEOPLE):
            if random.random() < 0.06:
                continue                                                    # a day off
            pc = f"WS-{i:03d}"
            t_in = dt.datetime.combine(day, dt.time(8, 0)) + dt.timedelta(minutes=random.gauss(20, 15))
            t_out = dt.datetime.combine(day, dt.time(17, 0)) + dt.timedelta(minutes=random.gauss(10, 25))
            lines += [ev(t_in, 4624, u, pc, LogonType="2", IpAddress="-"), ev(t_out, 4634, u, pc, LogonType="2")]
            lines.append(ev(t_in, 4624, pc + "$", pc, LogonType="3", IpAddress="-"))        # machine-account noise the adapter must drop
            if i % 5 == 0 and random.random() < 0.5:                                         # a few people use USB drives routinely
                lines.append(ev(t_in + dt.timedelta(hours=2), 6416, u, pc))
            if random.random() < 0.03:
                lines.append(ev(t_in - dt.timedelta(seconds=20), 4625, u, pc, LogonType="2", IpAddress="-"))
    night = dt.datetime.combine(BAD_DAY, dt.time(2, 10))
    lines += [ev(night, 4624, BAD_WHO, VICTIM_PC, LogonType="2", IpAddress="-"), ev(night + dt.timedelta(minutes=4), 6416, BAD_WHO, VICTIM_PC),
              ev(night + dt.timedelta(minutes=31), 4634, BAD_WHO, VICTIM_PC, LogonType="2")]
    random.shuffle(lines)
    with open(os.path.join(folder, "security.jsonl"), "w") as f:
        f.write("\n".join(lines))
    return len(lines)


def main():
    tmp = tempfile.mkdtemp(prefix="bw_test_")
    try:
        n = make_logs(os.path.join(tmp, "logs"))
        ws = Workspace.create(os.path.join(tmp, "watch"), "Test office", learn_until=str(START + dt.timedelta(days=49)),
                              sources=[{"name": "dc", "adapter": "windows", "path": "../logs", "options": {}}])
        added = pipeline.update(ws, sequence=False, log=lambda *a: None)
        print(f"wrote {n:,} raw events; the adapter kept {added:,} (machine accounts and network logons dropped)")
        assert 0 < added < n

        from fastapi.testclient import TestClient

        from watch import server
        server.load(ws.dir)
        c = TestClient(server.app)
        st = c.get("/api/state").json()
        assert st["scored"] and str(BAD_DAY) in st["days"]
        q = c.get("/api/queue", params={"day": str(BAD_DAY), "analyst": "Analyst 1"}).json()
        top = q["rows"][0]
        code = ws.code(BAD_WHO)
        print(f"{BAD_DAY}: {len(q['rows'])} alert(s); top is {top['code']} at risk {top['risk']}: {top['why']}")
        assert top["code"] == code, "the planted misuse is not at the top of its day"
        assert "name" not in top, "a name leaked before anyone asked for it"
        a = c.get("/api/alert", params={"code": code, "day": str(BAD_DAY), "analyst": "Analyst 1"}).json()
        assert a["timeline"][0]["t"] == "02:10" and a["timeline"][0]["w"] == "other", a["timeline"][:2]
        assert c.post("/api/reveal", json={"code": code, "analyst": "Analyst 1"}).status_code == 400            # no reason, no name
        r = c.post("/api/reveal", json={"code": code, "analyst": "Analyst 1", "reason": "Alert under review"}).json()
        assert r["account"] == BAD_WHO
        c.post("/api/decide", json={"code": code, "day": str(BAD_DAY), "state": "escalated", "analyst": "Analyst 1"})
        assert c.get("/api/queue", params={"day": str(BAD_DAY)}).json()["rows"][0]["state"] == "escalated"
        acts = [x["action"] for x in ws.audits()]
        assert "open" in acts and "reveal" in acts
        days = [d for d, n_ in zip(st["days"], st["alerts"]) if d >= ws.cfg["learn_until"]]
        total = sum(n_ for d, n_ in zip(st["days"], st["alerts"]) if d >= ws.cfg["learn_until"])
        print(f"alerts over the {len(days)} test days: {total} ({total / len(days):.1f} a day for {len(PEOPLE)} people); access log has {len(acts)} entries")

        # an analyst says USB drives are normal for this person: the alert must weaken, not vanish (the night logon remains)
        before = a["risk"]
        c.post("/api/expected", json={"who": "code:" + code, "what": "family:usb", "analyst": "Analyst 1"})
        after = c.get("/api/alert", params={"code": code, "day": str(BAD_DAY)}).json()
        print(f"after marking USB as expected for them: risk {before} -> {after['risk']}; reasons now {after['why'][:2]}")
        assert not any("USB" in w for w in after["why"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    samples = os.path.join(os.path.dirname(HERE), "data", "samples")
    win = sorted(glob.glob(os.path.join(samples, "windows", "*.json")))
    if win:
        import pandas as pd
        d = pd.concat([x for f in win for x in Windows({"timezone": "UTC"}).read(f)])
        print(f"real Windows samples (OTRF Security-Datasets): {len(win)} files -> {len(d)} events, {d.action.value_counts().to_dict()}")
        assert {"account_change", "logon_failed", "privileged"} <= set(d.action) and not d.actor.str.endswith("$").any()
    ssh = os.path.join(samples, "sshd", "OpenSSH_2k.log")
    if os.path.exists(ssh):
        import pandas as pd
        d = pd.concat(list(Sshd({"year": 2023}).read(ssh)))
        print(f"real sshd sample (LogHub OpenSSH): {len(d)} events, {d.action.value_counts().to_dict()}, {d.object.nunique()} source addresses")
        assert len(d) > 500
    print("ok")


if __name__ == "__main__":
    main()
