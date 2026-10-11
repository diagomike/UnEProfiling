"""Fetch the parts of the CERT Insider Threat Test Dataset r4.2 this prototype uses
(logon, device, file, LDAP and the answer key) from a Hugging Face mirror of the CMU
release (CC BY 4.0, https://doi.org/10.1184/R1/12841247). http.csv (14.5 GB) and
email.csv (1.4 GB) are left out. Resumable; safe to re-run."""
import os, sys, requests

BASE = "https://huggingface.co/datasets/jinmang2/cert_insider_threat/resolve/main/"
API = "https://huggingface.co/api/datasets/jinmang2/cert_insider_threat"
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the prototype now lives in attempts/; its data stays in ../data
WANT = sys.argv[1:] or ["logon.csv", "device.csv", "LDAP/", "psychometric.csv", "answers/"]

def get(path, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    for attempt in range(40):
        have = os.path.getsize(dest + ".part") if os.path.exists(dest + ".part") else 0
        try:
            r = requests.get(BASE + path, headers={"Range": f"bytes={have}-"} if have else {}, stream=True, timeout=60)
            if r.status_code == 416: break
            r.raise_for_status()
            with open(dest + ".part", "ab" if have and r.status_code == 206 else "wb") as f:
                for ch in r.iter_content(1 << 18): f.write(ch)
            break
        except Exception as e:
            print("retry", path, attempt, repr(e)[:120], flush=True)
    os.replace(dest + ".part", dest)

files = [s["rfilename"] for s in requests.get(API, timeout=60).json()["siblings"]]
for f in files:
    if f.startswith("r4.2/") and any(f[5:].startswith(w) or f[5:] == w for w in WANT):
        dest = os.path.join(HERE, "data", "cert_r4.2", f[5:])
    elif f.startswith("answers/") and "answers/" in WANT and (f.startswith("answers/r4.2") or f.count("/") == 1):
        dest = os.path.join(HERE, "data", f)
    else:
        continue
    if not os.path.exists(dest):
        get(f, dest); print("ok", f, os.path.getsize(dest), flush=True)
