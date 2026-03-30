"""Create a machine snapshot and optionally save it as JSON."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def bytes_to_gb(num_bytes: int) -> float:
    """Convert bytes to GB with 2 decimal places."""
    return round(num_bytes / (1024**3), 2)


def get_memory_info() -> dict[str, Any]:
    """Return memory details."""
    memory = psutil.virtual_memory()
    return {
        "total_gb": bytes_to_gb(memory.total),
        "available_gb": bytes_to_gb(memory.available),
        "used_gb": bytes_to_gb(memory.used),
        "percent_used": memory.percent,
    }


def get_disk_info(path: str = "/") -> dict[str, Any]:
    """Return disk usage details for a given path."""
    usage = shutil.disk_usage(path)
    return {
        "path": path,
        "total_gb": bytes_to_gb(usage.total),
        "used_gb": bytes_to_gb(usage.used),
        "free_gb": bytes_to_gb(usage.free),
    }


def get_network_info() -> dict[str, str]:
    """Return hostname and best-effort local IP address."""
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "unknown"
    return {"hostname": hostname, "local_ip": local_ip}


def build_snapshot(disk_path: str) -> dict[str, Any]:
    """Build and return the full snapshot dictionary."""
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "user": getpass.getuser(),
        "operating_system": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=0.5),
        },
        "memory": get_memory_info(),
        "disk": get_disk_info(disk_path),
        "network": get_network_info(),
        "uptime_seconds": int(datetime.now(timezone.utc).timestamp() - psutil.boot_time()),
    }


def save_snapshot(snapshot: dict[str, Any], output_dir: Path) -> Path:
    """Save snapshot as pretty JSON with timestamped file name."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"snapshot_{timestamp}.json"
    output_file.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return output_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a system snapshot.")
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save snapshot to a timestamped JSON file in ./snapshots",
    )
    parser.add_argument(
        "--output-dir",
        default="snapshots",
        help="Directory used when --save is enabled (default: snapshots)",
    )
    parser.add_argument(
        "--disk-path",
        default="C:\\" if os.name == "nt" else "/",
        help="Path used for disk usage stats (default: system root path)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    snapshot = build_snapshot(args.disk_path)

    print("System Snapshot")
    print(json.dumps(snapshot, indent=2))

    if args.save:
        output_file = save_snapshot(snapshot, Path(args.output_dir))
        print(f"\nSaved snapshot to: {output_file}")


if __name__ == "__main__":
    main()