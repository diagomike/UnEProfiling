# Setting up Behaviour Watch on your own logs

For the administrator who will point it at real logs. Nothing here needs the internet once
Python and the packages are installed.

## 1. Install

Python 3.10 or newer, then in this folder:

```
pip install -r requirements.txt
```

`torch` and `transformers` are only for the sequence model. On a machine without them the
watch still runs on the count detectors, and says so when it scores. A GPU is not needed:
the model has about 0.3 million parameters and trains on a laptop CPU.

## 2. Make a watch

A watch is a folder. Put it where the analysts can reach it; it will hold the normalised
logs and every decision they take, so treat it like the logs themselves.

```
python behaviour_watch.py new D:\watches\head-office --name "Head office" --source windows=D:\logs\security
```

That writes `D:\watches\head-office\watch.json`. Open it and adjust:

| Key | What it is |
|---|---|
| `sources` | One entry per log source: `name`, `adapter`, `path`, `options`. See below. |
| `hours` | Working hours (`start`, `end`, 24-hour clock) and `weekend` (weekday numbers, Monday = 0). Everything outside counts as after hours. |
| `learn_until` | A date. Alert thresholds and the sequence model learn from the days before it. Leave it out and the first 40% of days are used. Pick a stretch you believe was ordinary. |
| `baseline_days` | How many of a person's own recent active days they are compared with (60). |
| `alert_percentile` | A day raises an alert when it is stranger than this share of the learned days (99). Raise it for a shorter queue. |
| `analysts` | The names offered in the console's "Who are you?" list. |
| `pseudonyms` | `true`: people are shown as codes until an analyst gives a reason. |
| `sites` | Site categories (job search, leak sites, personal cloud storage, monitoring tools). Replace with your proxy's own categories if it has them. |
| `dismiss_reasons`, `reveal_reasons` | The lists analysts pick from. |

A `directory.csv` in the folder says who is who. Columns: `actor` (the account name as it
appears in the logs), `name`, `role`, `department`, `team`, `manager`, `left` (month the
account was closed, or empty). Export it from Active Directory. Without it the watch still
works, but there are no role comparisons and no names to reveal.

## 3. Log sources

### Windows Security log (`windows`)

Point `path` at a file or a folder of:

- `.evtx` files copied from `C:\Windows\System32\winevt\Logs\Security.evtx` (domain
  controllers for logons across the domain; workstations for USB events);
- JSON lines from Winlogbeat, Wazuh or NXLog (nested or flat field names are both read);
- a CSV from `Get-WinEvent ... | Export-Csv` that has the event id, time, computer and the
  event data fields as columns.

Events used: 4624 (logon; types 2, 7, 11 as interactive, 10 as remote), 4634 and 4647
(logoff), 4625 and 4771 (failed logon), 4648 (explicit credentials), 4672 (privileged
session), 4720 to 4756 (account and group changes), 1102 (audit log cleared), 6416 (new
external device, needs "Audit PNP Activity"), 4663 on removable storage (needs "Audit
Removable Storage"), 4688 (process creation).

Options: `timezone` (default `Africa/Addis_Ababa`; event times are stored in UTC and shown
in this zone), `network: true` to keep type 3 network logons (off by default: every file
share and printer makes them). Accounts ending in `$` and service identities are dropped.

### Linux auth logs (`sshd`)

`/var/log/auth.log` or `/var/log/secure`: sshd accepted and failed logons, and sudo commands.
Option `year` for logs whose timestamps have none.

### Anything in a table (`table`)

VPN, proxy, door-badge, application audit logs: any CSV. Name the columns in `options`:

```json
{"name": "vpn", "adapter": "table", "path": "D:/logs/vpn",
 "options": {"columns": {"ts": "login_time", "actor": "username", "host": "gateway", "object": "client_ip"},
             "action": "remote_logon", "time_format": "%d/%m/%Y %H:%M", "source": "vpn"}}
```

For a file with mixed events use `"action_column": "event", "action_map": {"LOGIN": "logon", "LOGOUT": "logoff"}`.
For a proxy log map the site to `object` and use `"action": "web_visit"`. The actions a log
can be mapped to are listed in `watch/events.py`.

Account names must match across sources (`jsmith` in one log and `JSMITH@corp` in another
are two people to the watch). Normalise them in the export if they differ.

## 4. Run it

```
python behaviour_watch.py update D:\watches\head-office      read new logs, then score
python behaviour_watch.py serve  D:\watches\head-office      open the console on this computer
```

`update` reads only files it has not read before (or that changed), so schedule it daily
with Task Scheduler after the day's logs are exported. The first run trains the sequence
model; later runs reuse it. Add `--retrain` after adding a new kind of log.

For several analysts, run the console on one machine and let the others use a browser:

```
python behaviour_watch.py serve D:\watches\head-office --lan --password CHOOSE-ONE
```

The password is sent with HTTP Basic authentication, in the clear unless you put the
console behind HTTPS. Use it on a trusted network segment only.

## 5. How much history it needs

A person is compared with their own previous days, so a count is not judged until that
person has 10 active days. Plan on four weeks of logs before the queue means much, and
eight before the sequence model has seen enough ordinary days.

## 6. What the watch folder holds

`events/` is the normalised copy of the logs (Parquet, one file per source and month).
`cases.jsonl` is every decision, appended and never rewritten. `audit.jsonl` is every time
an analyst opened a person's record or revealed a name, with the reason. Back the folder up
as you would the logs; restrict it with file permissions to the analysts.

## 7. Before it is used on staff

This is monitoring of employees. Ethiopia's Personal Data Protection Proclamation
No. 1321/2024 applies to it. Settle, in writing, who may see alerts, who may reveal names
and for which reasons, how long events and decisions are kept, and who reviews the access
log. The codes, the reasons and the access log exist so that those rules can be checked.
