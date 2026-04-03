# Python Log Analyzer

## Overview

A small Python tool that reads text logs, flags security-relevant lines (failed logins, errors, warnings, denials), aggregates IPs and timestamps, applies simple **statistical checks** (spikes, z-scores, rare lines, threshold alerts), optionally saves a **matplotlib** chart, **exports** JSON/CSV, and—when you want a research-style upgrade—runs **Isolation Forest** and **moving-average volume** checks in separate modules (`line_features.py`, `ml_anomaly.py`).

---

## Problem

Application and system logs are often the first place you see brute-force attempts, misconfiguration, and outages—but raw logs are noisy and easy to miss in. Turning logs into **counts, time buckets, ranked IPs, and alerts** makes patterns visible without a full SIEM, and sets the stage for heavier analytics or ML later.

---

## Approach

1. **Read** a log file (UTF-8, with replacement for invalid bytes).
2. **Classify** each line with a fixed keyword priority: `failed` → `error` → `warning` → `denied` (first match wins; same idea as a simple `if/elif` chain).
3. **Parse** a leading timestamp `YYYY-MM-DD HH:MM:SS` when present and bucket suspicious events **per minute**.
4. **Extract** IPv4 addresses from suspicious lines and count them with `collections.Counter`; track **failed-login lines per IP** separately for brute-force-style alerts.
5. **Report** summaries, time buckets, top IPs, then **anomaly-style** checks: per-minute spikes vs. the file’s average, duplicate-line “rarity,” z-score on minute totals, and fixed thresholds (total failed lines, many distinct IPs, **many failed lines from one IP**).
6. **Optionally** write a bar chart of suspicious events per minute to a PNG file, and/or **JSON** / **CSV** exports for dashboards or tickets.
7. **Optional ML mode (`--ml`)**: build a numeric feature vector per line (time-of-day, log level, length, IP count, keyword flags), **train** an `IsolationForest` on a **baseline** log (or unsupervised on the same file), **score** the target log, and compare **all-line volume per minute** to a trailing **moving average** (baseline-style drift in traffic).

---

## Tools & Technologies

- Python 3.10+ (uses `datetime | None` style types; adjust if you need older Python)
- `argparse`, `re`, `collections.Counter`, `statistics`
- Optional: `matplotlib`, `numpy`, `scikit-learn` (see [Dependencies](#dependencies))

---

## Features

- Keyword-based detection: failed login, error, warning, access denied (single primary label per line)
- Per-category counts and total suspicious line count
- IP extraction and **top IPs** (sorted by frequency)
- **Time buckets**: suspicious events per minute (when timestamps parse)
- **Anomaly-style helpers**: spike detection vs. mean, z-score on minute counts, “rare” exact duplicate lines among suspicious entries, threshold alerts (tunable constants in `log_analyzer.py`), including **per-IP failed-login counts** vs. a threshold
- Optional **PNG chart** (`log_analysis.png` by default)
- Optional **JSON** (full report) and **CSV** (per-IP suspicious vs. failed counts) export
- **Modular ML**: `line_features.py` (feature extraction), `ml_anomaly.py` (Isolation Forest + moving-average volume anomalies)
- CLI: log path, `--no-chart`, `--chart-out`, `--export-json`, `--export-csv`, **`--ml`**, **`--baseline`**, **`--ml-contamination`**

---

## Dependencies

```text
pip install -r requirements.txt
```

- **matplotlib** — chart (skipped if missing).
- **numpy** / **scikit-learn** — only needed for `--ml` (clear message if missing).

---

## Usage

```text
python log_analyzer.py [LOG_FILE] [--no-chart] [--chart-out PATH] [--export-json PATH] [--export-csv PATH]
  [--ml] [--baseline FILE] [--ml-contamination FLOAT]
```

- **`LOG_FILE`** — Path to the log file. If omitted, defaults to `sample.log`.
- **`--no-chart`** — Do not write a matplotlib PNG.
- **`--chart-out`** — Output path for the chart (default: `log_analysis.png`).
- **`--export-json`** — Write a JSON report (summary, IPs, time buckets, anomaly summary, alerts).
- **`--export-csv`** — Write a CSV with columns `ip`, `suspicious_line_count`, `failed_login_line_count`.
- **`--ml`** — Run Isolation Forest (line features) and moving-average volume checks (needs `numpy`, `scikit-learn`).
- **`--baseline`** — Optional “normal” log used **only to train** the Isolation Forest; the main `LOG_FILE` is scored. If omitted, the forest trains on the **same** file (unsupervised; needs enough lines—at least five with parseable features).
- **`--ml-contamination`** — Expected fraction of anomalies for the forest (default `0.08`, capped for sklearn).

Examples:

```text
python log_analyzer.py sample.log
python log_analyzer.py C:\logs\app.log --chart-out reports\activity.png
python log_analyzer.py sample.log --no-chart
python log_analyzer.py sample.log --export-json report.json --export-csv report.csv
python log_analyzer.py target.log --ml --baseline normal_week.log
python log_analyzer.py sample.log --no-chart --ml
```

---

## Example Output

Below is real output from `python log_analyzer.py sample.log --no-chart` (repository `sample.log`). With matplotlib installed and without `--no-chart`, the script also saves a chart and prints the saved path.

```text
=== Suspicious Entries ===
2026-03-20 10:02:01 WARNING Failed login from 203.0.113.7
2026-03-20 10:03:45 ERROR Access denied for admin from 198.51.100.25
2026-03-20 10:06:32 WARNING Failed login from 203.0.113.7
2026-03-20 10:03:45 ERROR Access denied for admin from 156.24.130.15

=== Summary ===
Failed: 2
Error: 2
Warning: 0
Denied: 0
Total suspicious lines: 4

=== Event frequency (by keyword category) ===
  failed   -> 2
  error    -> 2
  warning  -> 0
  denied   -> 0

=== Top IP addresses (suspicious lines) ===
  203.0.113.7 -> 2
  198.51.100.25 -> 1
  156.24.130.15 -> 1

=== Failed-login lines by IP ===
  203.0.113.7 -> 2

=== Time buckets (suspicious events per minute) ===
  2026-03-20 10:02 -> 1
  2026-03-20 10:03 -> 2
  2026-03-20 10:06 -> 1

=== Anomaly: activity spikes (per minute) ===
  (no spikes above tuned thresholds)

=== Anomaly: rare event lines (among suspicious) ===
  [1x] 2026-03-20 10:02:01 WARNING Failed login from 203.0.113.7
  [1x] 2026-03-20 10:03:45 ERROR Access denied for admin from 156.24.130.15
  [1x] 2026-03-20 10:03:45 ERROR Access denied for admin from 198.51.100.25
  [1x] 2026-03-20 10:06:32 WARNING Failed login from 203.0.113.7

=== Anomaly: z-score (minutes with suspicious events) ===
  (no minutes with z > 2)

=== Threshold alerts ===
  (no threshold alerts triggered)
```

With `--export-json` / `--export-csv`, an **Export** section lists the paths written (not shown above).

---

## Project Structure

```text
log-analyzer/
├── log_analyzer.py      # CLI + rule-based analytics
├── line_features.py     # Per-line numeric features for ML
├── ml_anomaly.py        # Isolation Forest + moving-average volume
├── sample.log
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Skills Demonstrated

- Python scripting and CLI design
- File I/O and structured reporting
- Regular expressions and light time-series aggregation
- Exploratory “anomaly” signals without ML (thresholds + basic statistics)
- Optional **Isolation Forest** on engineered features and **moving-average** volume anomalies (with optional baseline log)
- Optional visualization with matplotlib
- JSON/CSV export for reuse in spreadsheets or dashboards

---

## Future Improvements

- **Structured log formats** (JSON lines, syslog) with field parsers instead of substring keywords
- **Severity scoring** (numeric ranks per event type or message class)
- Stricter IP validation and extraction from more patterns
- **Richer ML**: learned embeddings, sequence models (LSTM/Transformer) on log lines, or template clustering (e.g. Drain) on top of the current feature pipeline
- **Multi-file** batch analysis and rolling baselines over time
- Config file or env vars for thresholds instead of constants in code

---

## Conclusion

The tool layers **rules and statistics** for transparency, **exports** for integration, and an optional **ML path** (baseline + Isolation Forest + volume MA) so you can describe both heuristic and learning-based anomaly detection in research write-ups (for example DREU).
