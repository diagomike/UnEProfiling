"""The one table every log becomes.

Whatever the source (a Windows security log, a proxy export, the CERT test data), an adapter
turns it into rows of: who did what, when, on which machine, to what. Everything after that
(baselines, detectors, the console) reads only this table, so adding a log source means
writing an adapter and nothing else.

    id        the source's own event id, kept so a known incident can be matched back
    ts        when (local time of the organisation)
    actor     the account that acted
    host      the machine it happened on ("" when the log does not say)
    action    one of ACTIONS
    object    what it was done to: a site, a file type, the outside mail domains, a target account
    amount    a count that belongs to the event (attachments, bytes moved); 0 when there is none
    external  the event reaches outside the organisation (an outside recipient, an outside address)
    source    which log it came from
"""
from __future__ import annotations

import pandas as pd

COLUMNS = ["id", "ts", "actor", "host", "action", "object", "amount", "external", "source"]

# action -> how it reads in a timeline
ACTIONS = {
    "logon": "Logged on", "logoff": "Logged off", "logon_failed": "Failed logon", "remote_logon": "Remote logon",
    "explicit_cred": "Used another account's credentials", "privileged": "Privileged session",
    "account_change": "Changed an account", "log_cleared": "Cleared an audit log",
    "usb_connect": "USB drive connected", "usb_disconnect": "USB drive removed",
    "file_to_usb": "File copied to USB", "file_access": "File accessed",
    "email_send": "Email sent", "web_visit": "Web visit", "web_upload": "Web upload", "web_download": "Web download",
    "process": "Program started", "sudo": "Ran a command as root",
}


def frame(n=None, **cols) -> pd.DataFrame:
    """Build a well-formed event table from whatever columns an adapter has; the rest get defaults."""
    n = len(next(iter(cols.values()))) if n is None else n
    d = pd.DataFrame({k: v for k, v in cols.items()})
    for c, default in (("id", ""), ("host", ""), ("object", ""), ("amount", 0.0), ("external", False), ("source", "")):
        if c not in d:
            d[c] = default
    d["ts"] = pd.to_datetime(d["ts"])
    for c in ("id", "actor", "host", "action", "object", "source"):
        d[c] = d[c].fillna("").astype(str)
    d["amount"] = pd.to_numeric(d["amount"], errors="coerce").fillna(0).astype("float32")
    d["external"] = d["external"].fillna(False).astype(bool)
    d = d[d.actor.ne("") & d.ts.notna() & d.action.isin(list(ACTIONS))]
    return d[COLUMNS]
