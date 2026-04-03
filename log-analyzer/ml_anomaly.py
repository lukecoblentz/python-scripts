"""
ML-style anomaly helpers: Isolation Forest on line features + moving-average
deviations on per-minute line volume (all lines with parseable timestamps).
"""

from __future__ import annotations

from collections import Counter
from statistics import mean, pstdev

from line_features import TS_PATTERN, lines_to_matrix

# Moving window (minutes) for baseline; flag if current count exceeds band
MA_WINDOW = 5
MA_Z_THRESHOLD = 2.0


def _minute_key(line: str) -> str | None:
    m = TS_PATTERN.match(line.strip())
    if not m:
        return None
    return m.group(1)[:16]  # YYYY-MM-DD HH:MM


def all_lines_per_minute(lines: list[str]) -> list[tuple[str, int]]:
    """Chronological (sorted) list of (minute_key, count of lines in that minute)."""
    c: Counter[str] = Counter()
    for line in lines:
        k = _minute_key(line)
        if k is not None:
            c[k] += 1
    return sorted(c.items())


def print_moving_average_deviations(lines: list[str]) -> None:
    """Compare each minute's total line count to a trailing moving average."""
    series = all_lines_per_minute(lines)
    if len(series) < 2:
        print("  (need at least two minutes with parseable timestamps)")
        return
    keys = [k for k, _ in series]
    values = [v for _, v in series]
    print(
        f"  Window={MA_WINDOW} minutes; flag if count > MA + {MA_Z_THRESHOLD} * std(window) "
        f"(when std > 0)"
    )
    flagged = False
    for i in range(len(values)):
        start = max(0, i - MA_WINDOW)
        past = values[start:i]
        if not past:
            continue
        m = mean(past)
        if len(past) >= 2:
            s = pstdev(past)
        else:
            s = 0.0
        v = values[i]
        if s > 0 and v > m + MA_Z_THRESHOLD * s:
            print(f"  DEVIATION: {keys[i]} -> {v} lines (MA≈{m:.2f}, σ≈{s:.2f})")
            flagged = True
    if not flagged:
        print("  (no strong deviations vs trailing moving average)")


def run_isolation_forest(
    target_lines: list[str],
    baseline_lines: list[str] | None,
    contamination: float,
) -> None:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        print(
            "  scikit-learn not installed. Install with: pip install scikit-learn\n"
            "  (also requires numpy)"
        )
        return

    X_train, _ = lines_to_matrix(baseline_lines if baseline_lines is not None else target_lines)
    X_test, test_idx = lines_to_matrix(target_lines)

    if X_train.shape[0] < 5:
        print(
            f"  (need at least 5 training lines with features; got {X_train.shape[0]}). "
            "Use a larger log or a --baseline file."
        )
        return
    if X_test.shape[0] < 1:
        print("  (no target lines to score)")
        return

    # sklearn expects contamination in (0, 0.5)
    c = min(max(contamination, 0.01), 0.45)
    model = IsolationForest(
        n_estimators=200,
        contamination=c,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    pred = model.predict(X_test)
    scores = model.decision_function(X_test)

    anom: list[tuple[float, int, str]] = []
    for row in range(X_test.shape[0]):
        if pred[row] == -1:
            li = test_idx[row]
            anom.append((float(scores[row]), li, target_lines[li].strip()))

    anom.sort(key=lambda t: t[0])
    src = "baseline file" if baseline_lines is not None else "same file (unsupervised)"
    print(f"  Trained on {X_train.shape[0]} lines from {src}; scored {X_test.shape[0]} target lines.")
    print(f"  contamination={c:.3f} (capped); lower score = more anomalous in IF sense.")
    if not anom:
        print("  (no lines labeled anomalous at this contamination setting)")
    else:
        print(f"  Flagged {len(anom)} line(s) (Isolation Forest):")
        for sc, _li, text in anom[:50]:
            short = text if len(text) <= 160 else text[:157] + "..."
            print(f"    score={sc:.4f}  {short}")
        if len(anom) > 50:
            print(f"    ... and {len(anom) - 50} more")


def run_ml_report(
    target_lines: list[str],
    baseline_lines: list[str] | None,
    contamination: float,
) -> None:
    print("\n=== ML: Isolation Forest (line-level features) ===")
    run_isolation_forest(target_lines, baseline_lines, contamination)

    print("\n=== ML: Volume vs moving average (all lines, per minute) ===")
    print_moving_average_deviations(target_lines)
