# Behaviour Watch

User and entity behaviour analytics on whatever logs an organisation has. It learns what
is normal for each person and each machine, raises the days that are not, says why in
plain words, and gives analysts a console to work the alerts in.

Built for INSA's externship brief ("user profiling, malicious usage detection, unusual
behaviour flagging and a comprehensive tooling", on open log data with LogBERT), and
measured on the one open dataset that has an organisation's logs over many months with a
known answer: Carnegie Mellon's CERT Insider Threat Test Dataset r4.2.

**Where it stands.** On CERT r4.2 with all five of its logs (32.7 million events), the queue holds 5.8 alerts a day for 1,000 employees, and 69 of the 70 scripted insiders appear in it, 48 of them within a week of their first act. On the 32 insiders held out while the scoring was designed it found all 32. The first prototype found 43 on two logs, counted differently (see "Measured"). The data is simulated and the figures are a ceiling, not a forecast: see "A trap in the test data". The console, the Windows, Linux and CSV adapters and the daily job all run; none has yet seen a real organisation's logs.

## Start here

```
pip install -r requirements.txt
python fetch_data.py                 CERT r4.2 logon, USB, file logs, directory, answer key (280 MB)
python fetch_data.py email web       the email and web logs, reduced as they download (1.75 GB of transfer)
python behaviour_watch.py demo       build the test watch: read, learn, score, measure (about 45 minutes on a laptop CPU)
python behaviour_watch.py serve      open the console at http://127.0.0.1:8770
```

On Windows, `Behaviour-Watch.cmd` does the last step. To run it on your own logs instead of
CERT, see [docs/SETUP.md](docs/SETUP.md).

To look without installing anything, open `demo/behaviour-watch.html` in a browser: the same
console, answering from a saved month of the scored test data (`build_demo.py` makes it).

## What the console does

| Screen | For |
|---|---|
| **Queue** | One day's alerts, strangest first. Each shows why it stands out, the person's counts against their own usual and their role's, the day event by event, and their risk over the last 90 days. `d` dismisses with a reason picked from a list, `w` watches, `e` escalates, `j`/`k` and the arrow keys move. |
| **People** | Who has raised alerts lately, and a profile of what is normal for each person: the hours they keep, the machines they use, a typical day in numbers, every day that raised an alert. |
| **Machines** | Computers behaving unlike themselves: new people logging on, USB activity it never had. |
| **Cases** | Everything being watched or escalated, every decision with its reason, and CSV exports for a report. |
| **Measured** | How the detectors do against known incidents, when the watch has any. |
| **Setup** | Log sources, "read new logs and re-score", behaviour marked as expected, thresholds, and the access log. |

Three things are in it because of what this tool is:

- **Names are hidden until someone gives a reason.** People appear as codes (`P-3FA2C1`).
  An analyst who needs the name picks why from a list, and that is written down.
- **Every look is logged.** Opening a person's alert or profile and revealing a name each
  add a line to `audit.jsonl`: who, when, whom, why. Setup shows it.
- **Analysts can teach it what is normal.** Beside any count that drove an alert, "normal?"
  marks it as expected for that person or for everyone in their role. The whole period is
  re-scored on the spot and the console says how many alerts that removed.

## How it works

```
logs ──adapters──▶ one event table ──▶ daily counts per person ──▶ deviation from own history ──▶ risk ──▶ queue
                   (who, what, when,    and per machine              deviation from role peers ─┐
                    which machine)      the day's event sequence ──▶ LogBERT surprise ──────────┴─▶ second opinions beside each alert
```

**Adapters** (`watch/adapters.py`) turn each log into the same table. There are four: the
CERT files, the Windows Security log (`.evtx`, Winlogbeat or Wazuh JSON, CSV exports), Linux
sshd and sudo logs, and a generic one for any CSV whose columns you name. Adding a source
is writing one class; nothing downstream changes.

**Counts** (`watch/features.py`). For every person and active day: logons, after-hours
logons, machines used, logons on someone else's machine, machines never used before, USB
connects, files and programs copied to USB, mail to outside addresses, outside
organisations never mailed before, sites never visited before, visits to sites few
colleagues use, and so on (24 counts on the CERT data). The same is done per machine.

**Deviation from own history.** Each count is compared with the person's own previous 60
active days and turned into "how unlikely is a count this high", taking the more cautious
of a Poisson reading (right for rare things: a first night logon is strong evidence, not
infinite evidence) and a reading against the count's own spread (right for busy, bursty
counts). Then each deviation is re-expressed as how seldom *that count* deviates that much
across everyone, so a count that jumps about for everybody says little and one that almost
never moves says a lot. A day's score is the sum of its two rarest deviations.

**Sequence model** (`watch/sequence.py`). LogBERT, the model INSA already uses on system
logs, adapted to people. It learns to predict masked events in ordinary days and scores a
day by its three least predictable events. Each sequence is the person's role and habits,
their last 24 events, then today's; each event is a token for what, when in the day and on
whose machine. About 0.3 million parameters, trained in 19 minutes on a laptop CPU.

**Risk.** A day's risk is where its own-history score falls among the days the watch
learned from, as a percentile; above the 99th it is an alert. Reasons are built from the
same counts that scored it, so nothing is flagged that cannot be explained. The sequence
model's percentile is shown beside each alert, and its surprise beside each event in the
day's timeline, as a second opinion. It does not rank the queue by default, because on
the test data it did not help (next section); `sequence_weight` in `watch.json` changes that.

## Measured on CERT r4.2

A simulated organisation of 1,000 employees over 17 months, with 70 scripted insiders in
three scenarios. Everything before 1 June 2010 is for learning (no insider is active yet);
the 351 days after are the test. An insider counts as found when at least one of their
scripted days raised an alert.

| Detector | Alerts a day | Insiders found (of 70) | In their first week | On their first day | Scenario 1 (of 30) | Scenario 2 (of 30) | Scenario 3 (of 10) | Alerts on an incident day | Found among the 32 held out |
|---|---|---|---|---|---|---|---|---|---|
| Random order | 6.5 | 10 | 2 | 0 | 2 | 8 | 0 | 0.4% | 7 |
| Role peers (counts against colleagues) | 5.9 | 48 | 40 | 30 | 24 | 14 | 10 | 5.3% | 21 |
| Sequence model (LogBERT) alone | 5.9 | 45 | 41 | 39 | 29 | 6 | 10 | 4.5% | 18 |
| Own baseline + sequence model (3:1) | 6.7 | 66 | 46 | 42 | 30 | 26 | 10 | 6.6% | 29 |
| **Own baseline (counts against own history)** (the queue) | 5.8 | **69** | **48** | 43 | 30 | 29 | 10 | 9.3% | **32** |

**What this says about LogBERT.** Alone, it finds the insiders whose day has an odd
event in it (a night logon, a USB drive on someone else's machine, a visit to a site
nobody uses): 39 of the 40 in scenarios 1 and 3. It misses scenario 2 (6 of 30), where no
single event is odd and the tell is a slow rise in ordinary things. The count detector
sees both, and once it has all five logs the sequence model adds nobody: blending the two
3:1 found three fewer insiders and raised more alerts on ordinary days. In the first prototype, with two logs,
LogBERT did add to a weaker count detector. So it stays in the tool as a second opinion and
as the per-event surprise in the timeline, and is worth re-testing on real logs, where the
counts will be noisier than CERT's. One implementation point mattered a great deal: summing
surprise over the whole day found 10 of the 38 development insiders, the three most
surprising events found 27. The sum mostly measures how much mail and browsing a day had.

Read with these in mind:

- **Half the insiders were held out.** Choices about how to score (which statistic, how
  many deviations to add up, how to use the sequence model) were made looking at 38 of
  the 70. The other 32 were scored only by the finished pipeline; the last column is that half.
- **"Found" is generous for long incidents.** A scenario 2 insider is active for about
  eight weeks, so even random alerts catch some. That is why the random row and the
  first-week column are in the table.
- **The first prototype is not comparable.** It reported 43 of 70 on two log sources, but
  counted only days with a scripted logon or USB event as incident days (322 of them). The
  answer key has 986, most of them days whose only scripted events are web visits. This
  version is scored against all 986, which is the honest target but also gives a long
  incident more days on which to be caught.

### A trap in the test data

In CERT r4.2 the number of web pages a person visits per day is all but constant. One employee
has exactly 143 visits on every one of 346 days; for 92% of people the daily total has a
standard deviation under three visits. The scripted insider visits are added on top, so *the raw daily total
alone* separates insider days almost perfectly (every one of the 38 development insiders,
34 of them on their first day, with one alert in five real). No real workforce browses
like that. Daily email totals are nearly as regular.

Behaviour Watch therefore shows these totals beside an alert but never scores them
(`context_only` in `watch.json`), and the table above is without them. Anyone benchmarking
insider detection on CERT should check whether their model is reading this constant. It is
also a reminder of the limit of all the numbers here: simulated people are more regular
than real ones, so these results are a ceiling, not a forecast.

### The web log

`http.csv` is 14.5 GB, nearly all of it page text. A third-party repackaging on Hugging
Face (`hizkai/Insider_Threat_Dataset`) carries each person's URLs and timestamps without
the text in 385 MB. Before using it I checked it against CMU's answer key: all 3,860
scripted web events are in it, at the same second and URL. It lacks the machine each visit
was made from. `python fetch_data.py http` fetches the original instead.

## Other open data, and what it was good for

| Data | Used for |
|---|---|
| OTRF Security-Datasets (Windows events from attack simulations) | Checking the `windows` adapter against real event shapes: 3 files, events for account creation, failed logons and privileged sessions parsed; machine accounts dropped. |
| LogHub OpenSSH (a real server's sshd log) | Checking the `sshd` adapter: 636 logon events from 25 source addresses in the 2,000-line sample. |
| LANL authentication data, CLUE-LDS | Not used. Both are several gigabytes and neither is labelled per person in a way that would add to CERT; LANL would be the next step on a faster connection. |

These samples are minutes long, so they test parsing, not detection. Detection on a second
kind of organisation is covered by `tests/own_logs_test.py`: it writes ten weeks of made-up
Windows events for a 40-person office with one planted night-time misuse, builds a watch
from nothing, and checks that the planted day tops its queue, that no name leaves the
server before a reason is given, and that the access log recorded it.

## Files

| Path | What it is |
|---|---|
| `watch/events.py` | The one event table and its vocabulary of actions. |
| `watch/adapters.py` | CERT, Windows Security, sshd, generic table. |
| `watch/workspace.py` | The watch folder: config, event store, decisions, access log. |
| `watch/features.py` | Daily counts, own-history and role-peer deviations. |
| `watch/sequence.py` | LogBERT for people. |
| `watch/detect.py` | Scores, reasons, evaluation. |
| `watch/pipeline.py` | Read, score, measure; the daily job. |
| `watch/server.py`, `watch/web/` | The console. |
| `fetch_data.py` | Fetches the open data, reducing the large logs as they download. |
| `tests/own_logs_test.py` | End-to-end test on made-up Windows logs and the real samples. |
| `docs/SETUP.md` | Running it on your own logs. |
| `build_demo.py`, `demo/` | Freezes the console and a month of the scored test watch into one page, `demo/behaviour-watch.html`, that needs no server. |
| `behaviour_watch.py`, `Behaviour-Watch.cmd` | Launchers: every command, from any folder; and a double-click start on Windows. |
| `attempts/` | The first prototype (two log sources, static page) and the two comparisons behind the choices above: how to add up count deviations, and how to use the sequence model. |

## Limits

- **Simulated data.** The method is shown to work; how it scores at INSA is unknown until
  it runs on INSA's logs with a few known incidents to check against.
- **Not real time.** It scores a day at a time from a daily job. That suits insider
  misuse, which unfolds over days; it is not an intrusion detector.
- **One organisation, one split.** Half the insiders were held out, but the ordinary staff
  are the same people in both halves.
- **Site categories are a hand-made list.** A real deployment should take them from the
  proxy's own categorisation.
- **Access control is light.** The console trusts whoever can reach it (or knows the
  `--lan` password) and takes the analyst's name from a list. Before real use it needs
  proper sign-in, and the watch folder needs file permissions.
- **Windows and Linux adapters have only parsed samples**, never a full organisation's logs.

## What INSA would need to supply

- Authentication logs from the domain controllers, USB and removable-storage auditing from
  workstations, proxy logs, and mail gateway logs: three months or more.
- A directory export (account, role, department, manager).
- A handful of confirmed past incidents, even five, to check the queue against.
- A decision on purpose and oversight under the Personal Data Protection Proclamation
  No. 1321/2024: who sees alerts, who may reveal names and why, how long data is kept.
