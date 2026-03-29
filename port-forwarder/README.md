# Port Forwarder

A Python TCP port forwarding tool built to practice socket programming, networking, and multithreading.

## What It Does

This script:
- Listens on a local TCP port
- Accepts incoming client connections
- Connects to a target host and port
- Forwards traffic between the client and target in both directions using multithreading

## How It Works

Traffic flows through the forwarder like this:

```text
Client -> Port Forwarder -> Target Server
Client <- Port Forwarder <- Target Server
```

Each connection is handled using:
- One thread per client
- Two relay threads:
  - Client -> Target
  - Target -> Client

## Test Setup

I tested this project locally by:

### 1. Starting a Python HTTP server

```bash
py -m http.server 8000
```

### 2. Running the port forwarder

```bash
py port_forwarder.py --listen-port 9999 --target-host 127.0.0.1 --target-port 8000
```

### 3. Visiting in browser

```text
http://127.0.0.1:9999
```

## Example Output

```text
Listening on 127.0.0.1:9999
Accepted connection from ('127.0.0.1', 35761)
Connected to remote target 127.0.0.1:8000
Client -> Target: received 460 bytes
Target -> Client: received 156 bytes
Target -> Client: received 328 bytes
Closed connection from ('127.0.0.1', 35761)
```

## Skills Demonstrated

- Python socket programming
- TCP networking fundamentals
- Multithreading
- Bidirectional data forwarding
- Command-line interface (argparse)
- Network traffic inspection and debugging

## Project Evolution

This project was built step-by-step:
- Basic single-request forwarder
- Added multi-chunk response handling
- Upgraded to threaded bidirectional forwarding
- Added CLI argument support using argparse

## Notes

- This tool is for learning and authorized testing only
- It is a simplified forwarder and not production-ready

## Future Improvements

- Error handling
- Logging system
- Support for multiple targets