"""Behaviour Watch from the command line.

    python -m watch new <folder> --name "Head office" --source windows=D:\\logs\\security
    python -m watch update <folder>           read new logs, then score          (the daily job)
    python -m watch read <folder>             only read new logs
    python -m watch score <folder>            only score        [--retrain] [--no-sequence]
    python -m watch measure <folder>          against known incidents
    python -m watch serve [<folder>]          open the console  [--port 8770] [--lan --password WORD]
    python -m watch demo                      build the CERT r4.2 watch from data fetched by fetch_data.py
"""
from __future__ import annotations

import argparse
import os
import sys

from . import pipeline
from .workspace import Workspace

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(HERE, "workspaces", "cert-r42")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m watch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["new", "update", "read", "score", "measure", "serve", "demo"])
    ap.add_argument("folder", nargs="?")
    ap.add_argument("--name"); ap.add_argument("--source", action="append", default=[], help="adapter=path (cert, windows, sshd, table); repeatable")
    ap.add_argument("--learn-until", help="YYYY-MM-DD: thresholds and the sequence model learn from before this date")
    ap.add_argument("--retrain", action="store_true"); ap.add_argument("--no-sequence", action="store_true")
    ap.add_argument("--port", type=int, default=8770); ap.add_argument("--lan", action="store_true"); ap.add_argument("--password", default="")
    a = ap.parse_args(argv)
    kw = {"sequence": not a.no_sequence, "retrain": a.retrain}

    if a.command == "demo":
        raw = os.path.join(HERE, "data", "cert_r4.2")
        if not os.path.exists(os.path.join(raw, "logon.csv")):
            sys.exit("Fetch the data first:  python fetch_data.py   (then, optionally, `python fetch_data.py email web`)")
        if not os.path.exists(os.path.join(DEMO, "watch.json")):
            Workspace.create(DEMO, "CERT r4.2 (test organisation)", learn_until="2010-06-01",
                             sources=[{"name": "cert", "adapter": "cert", "path": os.path.relpath(raw, DEMO), "options": {"release": "4.2"}}])
        pipeline.update(Workspace(DEMO), **kw)
        return
    if a.command == "serve":
        from . import server
        server.run(a.folder or (DEMO if os.path.exists(os.path.join(DEMO, "watch.json")) else None), port=a.port, lan=a.lan, password=a.password)
        return
    if not a.folder:
        ap.error("a watch folder is needed")
    if a.command == "new":
        srcs = []
        for i, s in enumerate(a.source):
            adapter, _, path = s.partition("=")
            srcs.append({"name": f"{adapter}{i + 1 if i else ''}", "adapter": adapter, "path": os.path.abspath(path), "options": {}})
        ws = Workspace.create(a.folder, a.name or os.path.basename(os.path.abspath(a.folder)), sources=srcs, learn_until=a.learn_until)
        print(f"created {ws.dir}\nedit watch.json to adjust sources, working hours and analysts; then: python behaviour_watch.py update \"{a.folder}\"")
        return
    ws = Workspace(a.folder)
    if a.command == "read":
        print(f"{ws.ingest():,} new events")
    elif a.command == "score":
        d, _, _ = pipeline.score(ws, **kw)
        if d.bad.any():
            pipeline.measure(ws, d)
    elif a.command == "measure":
        pipeline.measure(ws)
    elif a.command == "update":
        pipeline.update(ws, **kw)


if __name__ == "__main__":
    main()
