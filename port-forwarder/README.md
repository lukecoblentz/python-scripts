# Port Forwarder

A simple Python TCP port forwarding script built to practice socket programming and network traffic flow.

## What It Does

This script listens on a local TCP port, accepts an incoming connection, connects to a target host and port, and forwards traffic between the client and the target.

## Test Setup

I tested this project locally by:

1. Starting a simple Python HTTP server on `127.0.0.1:8000`
2. Running the port forwarder on `127.0.0.1:9999`
3. Opening `http://127.0.0.1:9999` in the browser

Traffic flow during testing:

```text
Browser -> Port Forwarder -> Local HTTP Server
Browser <- Port Forwarder <- Local HTTP Server