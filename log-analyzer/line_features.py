"""
Numeric feature vectors for each log line (used by Isolation Forest).
Kept separate from log_analyzer.py for modularity and testing.
"""

from __future__ import annotations

import re
from datetime import datetime

import numpy as np

TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
LEVEL_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (\w+)")
IP_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")


def line_to_features(line: str) -> np.ndarray | None:
    """Map one line to a fixed-length float vector. Skip empty lines."""
    stripped = line.strip()
    if not stripped:
        return None
    lower = stripped.lower()

    m = TS_PATTERN.match(stripped)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            time_of_day = dt.hour + dt.minute / 60.0 + dt.second / 3600.0
        except ValueError:
            time_of_day = 12.0
    else:
        time_of_day = 12.0

    lvl = 0.5
    lm = LEVEL_RE.match(stripped)
    if lm:
        word = lm.group(1).upper()
        if word in ("INFO", "DEBUG", "TRACE"):
            lvl = 0.0
        elif word in ("WARNING", "WARN"):
            lvl = 1.0
        elif word in ("ERROR", "CRITICAL", "FATAL"):
            lvl = 2.0
        else:
            lvl = 0.5

    ip_count = float(len(IP_PATTERN.findall(line)))
    line_len = min(len(stripped), 2000)

    return np.array(
        [
            time_of_day / 24.0,
            lvl / 2.0,
            float(line_len) / 500.0,
            min(ip_count, 10.0) / 10.0,
            1.0 if "failed" in lower else 0.0,
            1.0 if "error" in lower else 0.0,
            1.0 if "warning" in lower else 0.0,
            1.0 if "denied" in lower else 0.0,
        ],
        dtype=np.float64,
    )


def lines_to_matrix(lines: list[str]) -> tuple[np.ndarray, list[int]]:
    """Stack feature rows; return matrix and source line indices."""
    rows: list[np.ndarray] = []
    indices: list[int] = []
    for i, line in enumerate(lines):
        feat = line_to_features(line)
        if feat is not None:
            rows.append(feat)
            indices.append(i)
    if not rows:
        return np.zeros((0, 8), dtype=np.float64), []
    return np.vstack(rows), indices
