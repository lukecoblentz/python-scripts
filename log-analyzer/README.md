# Python Log Analyzer

## Overview

A small Python tool that reads text logs, flags security-relevant lines (failed logins, errors, warnings, denials), aggregates IPs and timestamps, applies simple **statistical checks** (spikes, z-scores, rare lines, threshold alerts), and optionally saves a **matplotlib** chart of activity over time.

---

## Problem

Application and system logs are often the first place you see brute-force attempts, misconfiguration, and outages—but raw logs are noisy and easy to miss in. Turning logs into **counts, time buckets, ranked IPs, and alerts** makes patterns visible without a full SIEM, and sets the stage for heavier analytics or ML later.

---

## Approach

1. **Read** a log file (UTF-8, with replacement for invalid bytes).
2. **Classify** each line with a fixed keyword priority: `failed` → `error` → `warning` → `denied` (first match wins; same idea as a simple `if/elif` chain).
3. **Parse** a leading timestamp `YYYY-MM-DD HH:MM:SS` when present and bucket suspicious events **per minute**.
4. **Extract** IPv4 addresses from suspicious lines and count them with `collections.Counter`.
5. **Report** summaries, time buckets, top IPs, then **anomaly-style** checks: per-minute spikes vs. the file’s average, duplicate-line “rarity,” z-score on minute totals, and optional fixed thresholds (e.g. many failed events or many distinct IPs).
6. **Optionally** write a bar chart of suspicious events per minute to a PNG file.

---

## Tools & Technologies

- Python 3.10+ (uses `datetime | None` style types; adjust if you need older Python)
- `argparse`, `re`, `collections.Counter`, `statistics`
- Optional: `matplotlib` (see [Dependencies](#dependencies))

---

## Features

- Keyword-based detection: failed login, error, warning, access denied (single primary label per line)
- Per-category counts and total suspicious line count
- IP extraction and **top IPs** (sorted by frequency)
- **Time buckets**: suspicious events per minute (when timestamps parse)
- **Anomaly-style helpers**: spike detection vs. mean, z-score on minute counts, “rare” exact duplicate lines among suspicious entries, threshold alerts (tunable constants in `log_analyzer.py`)
- Optional **PNG chart** (`log_analysis.png` by default)
- CLI: log path, `--no-chart`, `--chart-out`

---

## Dependencies

Install optional chart support:

```text
pip install -r requirements.txt
```

The script runs without matplotlib; chart output is skipped with a short message if it is not installed.

---

## Usage

```text
python log_analyzer.py [LOG_FILE] [--no-chart] [--chart-out PATH]
```

- **`LOG_FILE`** — Path to the log file. If omitted, defaults to `sample.log`.
- **`--no-chart`** — Do not write a matplotlib PNG.
- **`--chart-out`** — Output path for the chart (default: `log_analysis.png`).

Examples:

```text
python log_analyzer.py sample.log
python log_analyzer.py C:\logs\app.log --chart-out reports\activity.png
python log_analyzer.py sample.log --no-chart
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

---

## Project Structure

```text
log-analyzer/
├── log_analyzer.py
├── sample.log
├── requirements.txt
└── README.md
```

---

## Skills Demonstrated

- Python scripting and CLI design
- File I/O and structured reporting
- Regular expressions and light time-series aggregation
- Exploratory “anomaly” signals without ML (thresholds + basic statistics)
- Optional visualization with matplotlib

---

## Future Improvements

- Export summaries to **CSV/JSON** for dashboards or tickets
- **Structured log formats** (JSON lines, syslog) with field parsers
- Stricter IP validation and extraction from more patterns
- **Machine learning**: learn normal per-hour baselines from history, sequence models for log lines, or clustering/template extraction (e.g. Drain-like) for rarer template-level anomalies
- Config file or env vars for thresholds instead of constants in code

---

## Conclusion

This project shows how far you can get with keyword rules, aggregation, and simple statistics on a single log file—and where a chart or later ML could plug in when volume and history justify it.
