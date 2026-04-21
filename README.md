# PCAP Analyzer

A web-based network traffic analyzer that accepts packet captures and returns actionable insights through a FastAPI backend and a browser dashboard.

## What It Does

- Uploads a capture file and parses packets with Scapy
- Calculates traffic metrics such as total packet count and TCP/UDP share
- Shows top source and destination IP hosts
- Visualizes protocol and host distribution with charts
- Highlights suspicious or unusual destination ports with severity labels
- Generates an Analyst Summary in plain English with a quick risk note

## Architecture

- Single-process app: frontend and backend are served together by FastAPI
- Backend: packet parsing and analysis logic in `backend/analyzer.py`
- API server and static file serving in `backend/main.py`
- Frontend dashboard in `frontend/` (HTML, CSS, JS + Chart.js)

## Run The App

From the project root:

```bash
./run.sh
```

Default bind:

- Host: `0.0.0.0`
- Port: `8000`

Open in browser:

```text
http://127.0.0.1:8000
```

or from another device on your network:

```text
http://<your-machine-ip>:8000
```

Custom host/port:

```bash
HOST=0.0.0.0 PORT=8080 ./run.sh
```

Stop the app with `Ctrl+C`.

## File Support

- Backend currently accepts `.pcap` uploads via `/upload`.

## API

### `POST /upload`

Upload form field:

- `file` (PCAP file)

Response includes:

- `total_packets`
- `tcp_percentage`
- `udp_percentage`
- `top_source_ips`
- `top_destination_ips`
- `protocol_distribution`
- `top_ports` (with service label)
- `flagged_ports` (with context + severity)

## Dashboard Highlights

- KPI cards for total packets, TCP share, UDP share
- Analyst Summary panel with dominant protocol, busiest source host, busiest destination host, unusual ports observed, and a quick risk note
- Loading, success, and error status states
- Flagged ports table with severity badges (high/medium/low)

## Tech Stack

- Python
- FastAPI
- Scapy
- HTML/CSS/JavaScript
- Chart.js

## Troubleshooting

- If `./run.sh` fails, ensure the backend virtual environment exists at `backend/venv`.
- If changes do not appear in browser, hard refresh to clear cached static assets.