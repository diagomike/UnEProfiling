"""Fetch the open data Behaviour Watch is built and measured on.

CERT Insider Threat Test Dataset r4.2 (Carnegie Mellon SEI, CC BY 4.0,
https://doi.org/10.1184/R1/12841247), from a Hugging Face mirror of the CMU release:

    python fetch_data.py                 logon, device, file, LDAP, answer key (about 280 MB)
    python fetch_data.py email           the email log   (1.4 GB to download, about 150 MB kept)
    python fetch_data.py web             the web log without page text, repackaged (385 MB)
    python fetch_data.py http            the web log from the CMU file itself (14.5 GB to download;
                                         only needed if you want the PC of each visit)

The email and web logs are mostly message and page text, which nothing here reads. They
are reduced while they download: the text column is dropped and the rest is written as
Parquet parts under data/cert_r4.2/<name>/, so the big file never touches the disk.
Everything is resumable; an interrupted run carries on where it stopped.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import time

import requests

BASE = "https://huggingface.co/datasets/jinmang2/cert_insider_threat/resolve/main/"
API = "https://huggingface.co/api/datasets/jinmang2/cert_insider_threat"
HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "data", "cert_r4.2")
PLAIN = ["logon.csv", "device.csv", "file.csv", "LDAP/", "psychometric.csv", "answers/"]
# name -> the columns kept (everything but the text)
REDUCED = {"email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"],
           "http": ["id", "date", "user", "pc", "url"]}
PART_ROWS = 250_000            # a dropped connection loses at most this much progress


def get(path, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    for attempt in range(40):
        have = os.path.getsize(dest + ".part") if os.path.exists(dest + ".part") else 0
        try:
            r = requests.get(BASE + path, headers={"Range": f"bytes={have}-"} if have else {}, stream=True, timeout=60)
            if r.status_code == 416:
                break
            r.raise_for_status()
            with open(dest + ".part", "ab" if have and r.status_code == 206 else "wb") as f:
                for ch in r.iter_content(1 << 18):
                    f.write(ch)
            break
        except Exception as e:
            print("retry", path, attempt, repr(e)[:120], flush=True)
    os.replace(dest + ".part", dest)


def plain(want):
    files = [s["rfilename"] for s in requests.get(API, timeout=60).json()["siblings"]]
    for f in files:
        if f.startswith("r4.2/") and any(f[5:].startswith(w) for w in want):
            dest = os.path.join(RAW, f[5:])
        elif f.startswith("answers/") and "answers/" in want and (f.startswith("answers/r4.2") or f.count("/") == 1):
            dest = os.path.join(HERE, "data", f)
        else:
            continue
        if not os.path.exists(dest):
            get(f, dest)
            print("ok", f, os.path.getsize(dest), flush=True)


def reduced(name, limit_bytes=None):
    """Stream <name>.csv, keep REDUCED[name], write Parquet parts. State (bytes consumed up to the
    last complete row written) is kept beside the parts, so a restart asks the server for the rest."""
    import pandas as pd

    keep = REDUCED[name]
    out = os.path.join(RAW, name)
    os.makedirs(out, exist_ok=True)
    state_f = os.path.join(out, "_state.json")
    st = json.load(open(state_f)) if os.path.exists(state_f) else {"bytes": 0, "parts": 0, "rows": 0, "header": None, "done": False}
    if st["done"]:
        print(name, "already complete:", st["rows"], "rows"); return
    total = int(requests.head(BASE + f"r4.2/{name}.csv", allow_redirects=True, timeout=60).headers.get("Content-Length", 0))
    rows, t0, got0 = [], time.time(), st["bytes"]

    def flush(consumed, final=False):
        if rows:
            d = pd.DataFrame(rows, columns=keep)
            d["date"] = pd.to_datetime(d["date"], format="%m/%d/%Y %H:%M:%S")
            for c in keep:
                if c in ("size", "attachments"):
                    d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0).astype("int32")
            if "url" in d:                        # the site is what behaviour is read from; the page path is not kept
                d["domain"] = d.pop("url").str.extract(r"^[a-z]+://(?:www\.)?([^/:]+)", expand=False).fillna("?").astype("category")
            for c in ("user", "pc"):
                d[c] = d[c].astype("category")
            d.to_parquet(os.path.join(out, f"part-{st['parts']:04d}.parquet"), index=False)
            st["parts"] += 1; st["rows"] += len(rows); rows.clear()
        st["bytes"] = consumed; st["done"] = final
        json.dump(st, open(state_f + ".tmp", "w")); os.replace(state_f + ".tmp", state_f)
        rate = (consumed - got0) / max(time.time() - t0, 1) / 1e6
        left = (total - consumed) / 1e6 / max(rate, 1e-6) / 60 if total else 0
        print(f"{name}: {consumed / 1e6:,.0f} of {total / 1e6:,.0f} MB, {st['rows']:,} rows kept, {rate:.2f} MB/s, about {left:.0f} min left", flush=True)

    consumed = st["bytes"]                       # bytes of the remote file fully turned into rows
    for attempt in range(200):
        try:
            end = f"{limit_bytes - 1}" if limit_bytes else ""
            r = requests.get(BASE + f"r4.2/{name}.csv", headers={"Range": f"bytes={consumed}-{end}"}, stream=True, timeout=60)
            if r.status_code == 416:
                break
            r.raise_for_status()
            tail = b""
            for chunk in r.iter_content(1 << 20):
                buf = tail + chunk
                cut = buf.rfind(b"\n")
                if cut < 0:
                    tail = buf; continue
                block, tail = buf[:cut + 1], buf[cut + 1:]
                rd = csv.reader(io.StringIO(block.decode("utf-8", "replace")))
                for row in rd:
                    if st["header"] is None:
                        st["header"] = row; st["cols"] = [row.index(c) for c in keep]; continue
                    if len(row) >= len(st["header"]) - 1:
                        rows.append([row[i] if i < len(row) else "" for i in st["cols"]])
                consumed += len(block)
                if len(rows) >= PART_ROWS:
                    flush(consumed)
            if tail.strip() and not limit_bytes:   # last line without a newline
                row = next(csv.reader(io.StringIO(tail.decode("utf-8", "replace"))))
                rows.append([row[i] if i < len(row) else "" for i in st["cols"]]); consumed += len(tail)
            flush(consumed, final=not limit_bytes)
            break
        except Exception as e:
            print("retry", name, attempt, repr(e)[:160], flush=True)
            rows.clear(); consumed = st["bytes"]   # go back to the last part written
            time.sleep(min(60, 2 + attempt * 2))


WEB_ZIP = "https://huggingface.co/datasets/hizkai/Insider_Threat_Dataset/resolve/main/CERT_R42.zip"


def web():
    """The web log without its page text, from a third-party repackaging of http.csv: one row per
    user and period holding that user's URLs and timestamps (385 MB against 14.5 GB). It has no PC
    column. Checked against CMU's answer key: every red-team web event is in it, to the second.
    Written in the same shape as `reduced("http")`, under data/cert_r4.2/http/."""
    import zipfile

    import pandas as pd

    out = os.path.join(RAW, "http")
    if os.path.exists(os.path.join(out, "_state.json")):
        print("web log already present"); return
    box = os.path.join(HERE, "data", "cert_r4.2_web_repack")      # the archive stays in a folder of its own
    os.makedirs(box, exist_ok=True); os.makedirs(out, exist_ok=True)
    z = os.path.join(box, "CERT_R42.zip")
    for attempt in range(60):
        have = os.path.getsize(z) if os.path.exists(z) else 0
        try:
            r = requests.get(WEB_ZIP, headers={"Range": f"bytes={have}-"} if have else {}, stream=True, timeout=60)
            if r.status_code == 416:
                break
            r.raise_for_status()
            total = have + int(r.headers.get("Content-Length", 0)); t0 = time.time(); got = 0
            with open(z, "ab" if have and r.status_code == 206 else "wb") as f:
                for ch in r.iter_content(1 << 20):
                    f.write(ch); got += len(ch)
                    if got % (32 << 20) < (1 << 20):
                        print(f"web: {(have + got) / 1e6:,.0f} of {total / 1e6:,.0f} MB, {got / 1e6 / max(time.time() - t0, 1):.2f} MB/s", flush=True)
            break
        except Exception as e:
            print("retry web", attempt, repr(e)[:160], flush=True); time.sleep(5)
    rows, n = 0, 0
    with zipfile.ZipFile(z) as zf:
        for name in ("train_df", "test_df", "oot_df"):
            with zf.open(f"CERT_R42/{name}.parquet") as f:
                d = pd.read_parquet(io.BytesIO(f.read()), columns=["sample_id", "urls", "timestamps"])
            for i in range(0, len(d), 100):                       # 100 users at a time keeps memory flat
                p = d.iloc[i:i + 100]
                u = p.urls.str.split("~").explode()
                e = pd.DataFrame({"date": pd.to_datetime(p.timestamps.str.split("~").explode().values),
                                  "user": p.sample_id.loc[u.index].values,
                                  "domain": u.str.extract(r"^[a-z]+://(?:www\.)?([^/:]+)", expand=False).fillna("?").values})
                e["user"] = e.user.astype("category"); e["domain"] = e.domain.astype("category")
                e.to_parquet(os.path.join(out, f"part-{n:04d}.parquet"), index=False)
                n += 1; rows += len(e)
            print(f"web: {name} done, {rows:,} events so far", flush=True)
    json.dump({"done": True, "rows": rows, "parts": n, "source": WEB_ZIP}, open(os.path.join(out, "_state.json"), "w"))


if __name__ == "__main__":
    args = sys.argv[1:]
    if "web" in args:
        args.remove("web"); web()
        if not args:
            sys.exit()
    limit = None
    if "--first-mb" in args:                      # for trying the reducer on the start of a file
        i = args.index("--first-mb"); limit = int(args[i + 1]) << 20; del args[i:i + 2]
    names = [a for a in args if a in REDUCED]
    if not args or [a for a in args if a not in REDUCED]:
        plain([a for a in args if a not in REDUCED] or PLAIN)
    for n in names:
        reduced(n, limit)
