# Attempts

What was tried on the way to `watch/`, kept so the numbers in the reports can be re-run.

| File | What it is |
|---|---|
| `v1_prepare.py`, `v1_features.py`, `v1_logbert.py`, `v1_build_demo.py` | The first prototype (10 October 2026): CERT r4.2 logon and USB logs only, z-scores against a trailing baseline, LogBERT, and a static review page (`v1_template.html`, built to `v1_demo.html`). Run in that order from this folder. It found 43 of 70 insiders, counting only days with a scripted logon or USB event as incident days. |
| `v1_fetch_data.py` | Its downloader, superseded by `../fetch_data.py`. |
| `v2_scoring_choices.py` | The comparison behind the scoring in `watch/detect.py`: ways of adding up deviations, tried on the development half of the insiders only. `--each` scores every count alone; `--volume` puts the daily web and email totals back in, which shows the trap described in the main README. |
| `v2_sequence_choices.py` | How the sequence model's per-event surprise should become a day's score (sum, maximum, top three, excess over what is usual for that kind of event), and whether blending it with the count detector helps. Also on the development half only. |
