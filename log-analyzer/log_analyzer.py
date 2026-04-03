"""
Log analyzer: keyword-based events, IP aggregation, time buckets,
simple spike/rare/threshold checks, optional matplotlib chart.
"""

from __future__ import annotations

import argparse
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
    if failed_count >= ALERT_MIN_FAILED:
        print(f"  ALERT: failed events ({failed_count}) >= {ALERT_MIN_FAILED}")
    if len(ip_counts) >= ALERT_MIN_UNIQUE_SUSPICIOUS_IPS:
        print(
            f"  ALERT: unique IPs on suspicious lines ({len(ip_counts)}) "
            f">= {ALERT_MIN_UNIQUE_SUSPICIOUS_IPS}"
        )
    if failed_count < ALERT_MIN_FAILED and len(ip_counts) < ALERT_MIN_UNIQUE_SUSPICIOUS_IPS:
        print("  (no threshold alerts triggered)")

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
