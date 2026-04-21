# PCAP Analyzer

A web-based PCAP traffic analyzer built with FastAPI and Scapy.

## Run the backend

Run the full app from the repository root. FastAPI serves both the API and the frontend UI.

Foreground mode:

```bash
./run.sh
```

By default the app is reachable on your network at:

```text
http://<your-machine-ip>:8000
```

Optional custom host/port:

```bash
HOST=0.0.0.0 PORT=8080 ./run.sh
```

## Features
- Upload PCAP files
- Analyze packet metadata
- Show top source and destination IPs
- Show protocol distribution
- Flag suspicious ports

## Tech Stack
- Python
- FastAPI
- Scapy
- HTML/CSS/JavaScript
- Chart.js