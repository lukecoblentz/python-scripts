"""
Log analyzer: keyword-based events, IP aggregation, time buckets,
spike/rare/threshold checks, optional matplotlib chart, JSON/CSV export,
and optional ML (--ml: Isolation Forest + moving-average volume; see ml_anomaly.py).
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev

# Leading timestamp: YYYY-MM-DD HH:MM:SS
TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
IP_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")

# Tunable anomaly / alert thresholds
SPIKE_MULTIPLIER = 2.0
SPIKE_MIN_COUNT = 3
RARE_MAX_COUNT = 1
ALERT_MIN_FAILED = 5
ALERT_MIN_UNIQUE_SUSPICIOUS_IPS = 8
# Flag an IP if it appears on this many *failed-login* lines (brute-force style)
ALERT_FAILED_EVENTS_PER_IP = 3


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze a log file for suspicious patterns.")
    p.add_argument(
        "log_file",
        type=Path,
        nargs="?",
        default=Path("sample.log"),
        help="Path to log file (default: sample.log)",
    )
    p.add_argument(
        "--no-chart",
        action="store_true",
        help="Skip writing the matplotlib PNG chart.",
    )
    p.add_argument(
        "--chart-out",
        type=Path,
        default=Path("log_analysis.png"),
        help="Output path for the event frequency chart (default: log_analysis.png)",
    )
    p.add_argument(
        "--export-json",
        type=Path,
        metavar="PATH",
        help="Write a JSON report (summary, IPs, time buckets, anomaly flags).",
    )
    p.add_argument(
        "--export-csv",
        type=Path,
        metavar="PATH",
        help="Write a CSV table: ip, suspicious_line_count, failed_line_count.",
    )
    p.add_argument(
        "--ml",
        action="store_true",
        help=(
            "Run ML-style checks: Isolation Forest on line features, "
            "and per-minute volume vs moving average (requires scikit-learn, numpy)."
        ),
    )
    p.add_argument(
        "--baseline",
        type=Path,
        metavar="FILE",
        help=(
            "Normal/baseline log for training Isolation Forest (optional). "
            "If omitted, the main log file is used for training (unsupervised)."
        ),
    )
    p.add_argument(
        "--ml-contamination",
        type=float,
        default=0.08,
        help="Expected fraction of anomalies for Isolation Forest (default: 0.08).",
    )
    return p.parse_args()


def parse_timestamp(line: str) -> datetime | None:
    m = TS_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def classify_event(lower_line: str) -> str | None:
    """Single primary label per line (same priority as original script)."""
    if "failed" in lower_line:
        return "failed"
    if "error" in lower_line:
        return "error"
    if "warning" in lower_line:
        return "warning"
    if "denied" in lower_line:
        return "denied"
    return None


def main() -> None:
    args = parse_args()
    path = args.log_file
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    failed_count = error_count = warning_count = denied_count = 0
    ip_counts: Counter[str] = Counter()
    failed_per_ip: Counter[str] = Counter()
    events_per_minute: Counter[str] = Counter()
    suspicious_line_texts: list[str] = []

    print("\n=== Suspicious Entries ===")
    for line in lines:
        if not line.strip():
            continue
        lower_line = line.lower()
        label = classify_event(lower_line)
        if label is None:
            continue

        if label == "failed":
            failed_count += 1
        elif label == "error":
            error_count += 1
        elif label == "warning":
            warning_count += 1
        else:
            denied_count += 1

        print(line.strip())
        suspicious_line_texts.append(line.strip())

        dt = parse_timestamp(line)
        if dt is not None:
            bucket = dt.strftime("%Y-%m-%d %H:%M")
            events_per_minute[bucket] += 1

        for ip in IP_PATTERN.findall(line):
            ip_counts[ip] += 1
            if label == "failed":
                failed_per_ip[ip] += 1

    total_suspicious = failed_count + error_count + warning_count + denied_count

    print("\n=== Summary ===")
    print("Failed:", failed_count)
    print("Error:", error_count)
    print("Warning:", warning_count)
    print("Denied:", denied_count)
    print("Total suspicious lines:", total_suspicious)

    print("\n=== Event frequency (by keyword category) ===")
    print(f"  failed   -> {failed_count}")
    print(f"  error    -> {error_count}")
    print(f"  warning  -> {warning_count}")
    print(f"  denied   -> {denied_count}")

    print("\n=== Top IP addresses (suspicious lines) ===")
    if not ip_counts:
        print("  (none)")
    else:
        for ip, count in ip_counts.most_common():
            print(f"  {ip} -> {count}")

    print("\n=== Failed-login lines by IP ===")
    if not failed_per_ip:
        print("  (none)")
    else:
        for ip, count in failed_per_ip.most_common():
            print(f"  {ip} -> {count}")

    print("\n=== Time buckets (suspicious events per minute) ===")
    if not events_per_minute:
        print("  (no parseable timestamps on suspicious lines)")
    else:
        for bucket in sorted(events_per_minute.keys()):
            print(f"  {bucket} -> {events_per_minute[bucket]}")

    # --- Anomaly: spikes in per-minute activity ---
    print("\n=== Anomaly: activity spikes (per minute) ===")
    counts = list(events_per_minute.values())
    if len(counts) < 2:
        print("  (need at least two minutes with suspicious events to compare)")
    else:
        avg = mean(counts)
        for bucket in sorted(events_per_minute.keys()):
            c = events_per_minute[bucket]
            if c >= SPIKE_MIN_COUNT and c > avg * SPIKE_MULTIPLIER:
                print(
                    f"  SPIKE: {bucket} -> {c} events "
                    f"(avg {avg:.2f}, threshold ~{max(SPIKE_MIN_COUNT, avg * SPIKE_MULTIPLIER):.2f})"
                )
        if not any(
            events_per_minute[b] >= SPIKE_MIN_COUNT
            and events_per_minute[b] > mean(counts) * SPIKE_MULTIPLIER
            for b in events_per_minute
        ):
            print("  (no spikes above tuned thresholds)")

    # --- Anomaly: rare repeated message bodies (exact line text among suspicious) ---
    print("\n=== Anomaly: rare event lines (among suspicious) ===")
    line_freq = Counter(suspicious_line_texts)
    rare = [line for line, n in line_freq.items() if n <= RARE_MAX_COUNT]
    if not rare:
        print("  (none)")
    else:
        for line in sorted(rare):
            print(f"  [{line_freq[line]}x] {line}")

    # --- Optional: z-score on minute counts ---
    print("\n=== Anomaly: z-score (minutes with suspicious events) ===")
    if len(counts) >= 2:
        mu = mean(counts)
        sigma = pstdev(counts)
        if sigma == 0:
            print("  (all bucket counts identical — no z-score outliers)")
        else:
            for bucket in sorted(events_per_minute.keys()):
                c = events_per_minute[bucket]
                z = (c - mu) / sigma
                if z > 2.0:
                    print(f"  HIGH z={z:.2f}: {bucket} -> {c} events")
            if not any(
                (events_per_minute[b] - mu) / sigma > 2.0 for b in events_per_minute
            ):
                print("  (no minutes with z > 2)")
    else:
        print("  (not enough buckets)")

    # --- Threshold alerts ---
    print("\n=== Threshold alerts ===")
    alerts: list[str] = []
    if failed_count >= ALERT_MIN_FAILED:
        msg = f"ALERT: total failed-login lines ({failed_count}) >= {ALERT_MIN_FAILED}"
        print(f"  {msg}")
        alerts.append(msg)
    if len(ip_counts) >= ALERT_MIN_UNIQUE_SUSPICIOUS_IPS:
        msg = (
            f"ALERT: unique IPs on suspicious lines ({len(ip_counts)}) "
            f">= {ALERT_MIN_UNIQUE_SUSPICIOUS_IPS}"
        )
        print(f"  {msg}")
        alerts.append(msg)
    for ip, n in failed_per_ip.items():
        if n >= ALERT_FAILED_EVENTS_PER_IP:
            msg = (
                f"ALERT: IP {ip} has {n} failed-login lines "
                f"(>= {ALERT_FAILED_EVENTS_PER_IP})"
            )
            print(f"  {msg}")
            alerts.append(msg)
    if not alerts:
        print("  (no threshold alerts triggered)")

    if args.ml:
        from ml_anomaly import run_ml_report

        baseline_lines: list[str] | None = None
        if args.baseline is not None:
            bp = args.baseline
            if not bp.is_file():
                raise SystemExit(f"Baseline file not found: {bp}")
            baseline_lines = bp.read_text(encoding="utf-8", errors="replace").splitlines()
        run_ml_report(lines, baseline_lines, args.ml_contamination)

    # --- Optional JSON / CSV export ---
    if args.export_json or args.export_csv:
        spike_entries: list[dict[str, float | str | int]] = []
        if len(counts) >= 2:
            avg_spike = mean(counts)
            for bucket in sorted(events_per_minute.keys()):
                c = events_per_minute[bucket]
                if c >= SPIKE_MIN_COUNT and c > avg_spike * SPIKE_MULTIPLIER:
                    spike_entries.append(
                        {
                            "minute": bucket,
                            "count": c,
                            "avg_per_minute": round(avg_spike, 4),
                        }
                    )
        z_entries: list[dict[str, float | str | int]] = []
        if len(counts) >= 2:
            mu_z = mean(counts)
            sigma_z = pstdev(counts)
            if sigma_z > 0:
                for bucket in sorted(events_per_minute.keys()):
                    c = events_per_minute[bucket]
                    z = (c - mu_z) / sigma_z
                    if z > 2.0:
                        z_entries.append(
                            {"minute": bucket, "count": c, "z": round(float(z), 4)}
                        )
        rare_lines = [line for line, n in Counter(suspicious_line_texts).items() if n <= RARE_MAX_COUNT]

        report: dict = {
            "source": str(path.resolve()),
            "summary": {
                "failed": failed_count,
                "error": error_count,
                "warning": warning_count,
                "denied": denied_count,
                "total_suspicious_lines": total_suspicious,
            },
            "ip_suspicious": dict(ip_counts.most_common()),
            "ip_failed_login_lines": dict(failed_per_ip.most_common()),
            "events_per_minute": dict(sorted(events_per_minute.items())),
            "threshold_alerts": alerts,
            "anomalies": {
                "spikes": spike_entries,
                "z_score_over_2": z_entries,
                "rare_suspicious_line_count": len(rare_lines),
            },
            "thresholds": {
                "SPIKE_MULTIPLIER": SPIKE_MULTIPLIER,
                "SPIKE_MIN_COUNT": SPIKE_MIN_COUNT,
                "ALERT_MIN_FAILED": ALERT_MIN_FAILED,
                "ALERT_MIN_UNIQUE_SUSPICIOUS_IPS": ALERT_MIN_UNIQUE_SUSPICIOUS_IPS,
                "ALERT_FAILED_EVENTS_PER_IP": ALERT_FAILED_EVENTS_PER_IP,
            },
        }

        if args.export_json:
            out = args.export_json
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\n=== Export ===\n  JSON: {out.resolve()}")

        if args.export_csv:
            out_csv = args.export_csv
            out_csv.parent.mkdir(parents=True, exist_ok=True)
            all_ips = sorted(set(ip_counts) | set(failed_per_ip))
            with out_csv.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip", "suspicious_line_count", "failed_login_line_count"])
                for ip in all_ips:
                    w.writerow([ip, ip_counts[ip], failed_per_ip[ip]])
            print(f"  CSV: {out_csv.resolve()}")

    # --- Chart ---
    if not args.no_chart and events_per_minute:
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print(
                "\n=== Chart ===\n"
                "  matplotlib not installed; skipped. "
                "Install with: pip install matplotlib"
            )
        else:
            labels = sorted(events_per_minute.keys())
            values = [events_per_minute[k] for k in labels]
            fig, ax = plt.subplots(figsize=(10, 4))
            ax.bar(range(len(labels)), values, color="steelblue", edgecolor="navy", alpha=0.85)
            ax.set_xticks(range(len(labels)))
            ax.set_xticklabels(labels, rotation=45, ha="right")
            ax.set_ylabel("Suspicious events")
            ax.set_title("Suspicious events per minute")
            ax.grid(axis="y", linestyle="--", alpha=0.4)
            fig.tight_layout()
            out = args.chart_out
            fig.savefig(out, dpi=150)
            plt.close(fig)
            print(f"\n=== Chart ===\n  Saved: {out.resolve()}")


if __name__ == "__main__":
    main()
