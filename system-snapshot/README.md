# System Snapshot (Python)

A small CLI tool that captures key machine information and outputs a readable JSON snapshot.

## What it captures

- Current user
- OS and machine details
- Python version/runtime
- CPU core counts and usage
- Memory stats
- Disk usage for a chosen path
- Hostname/IP
- Uptime in seconds

## Why this is portfolio-friendly

- Uses clean function-based structure
- Includes CLI arguments with `argparse`
- Produces structured JSON for automation
- Can save timestamped snapshot files

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Print snapshot to terminal:

```bash
python system_snapshot.py
```

Print and save to `snapshots/`:

```bash
python system_snapshot.py --save
```

Save to a custom folder:

```bash
python system_snapshot.py --save --output-dir output
```

Check a custom disk path:

```bash
python system_snapshot.py --disk-path D:\
```

## Example interview explanation

"This script gathers system metrics using Python's standard library plus `psutil`, then normalizes values into a JSON document. I designed it as a CLI so the same script works for local checks, scripting, and logging snapshots over time."
