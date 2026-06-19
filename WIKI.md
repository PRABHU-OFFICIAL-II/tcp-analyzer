# TCP Analyzer — Internal Utility Documentation

**Audience:** Network engineers, SREs, security analysts, and support teams within Informatica / Salesforce  
**Access:** Runs locally on any machine via the install scripts — `http://localhost:5173`  
**Owner:** Penthoi, Prabhu Prasad  
**Last Updated:** June 2026

---

## Table of Contents

1. [What Is TCP Analyzer?](#1-what-is-tcp-analyzer)
2. [Why It Exists](#2-why-it-exists)
3. [Live Deployment](#3-live-deployment)
4. [System Architecture](#4-system-architecture)
5. [Technology Stack](#5-technology-stack)
6. [Analysis Modules](#6-analysis-modules)
7. [Report Viewer Features](#7-report-viewer-features)
8. [Supported File Formats](#8-supported-file-formats)
9. [User Workflow](#9-user-workflow)
10. [Installation](#10-installation)
11. [Configuration](#11-configuration)
12. [API Reference](#12-api-reference)
13. [Roadmap — Embedded AI Analysis](#13-roadmap--embedded-ai-analysis)
14. [Maintenance and Ownership](#14-maintenance-and-ownership)

---

## 1. What Is TCP Analyzer?

TCP Analyzer is a custom, internally developed full-stack web application that automates the analysis of network packet captures (PCAP files). It eliminates the immediate need for Wireshark or command-line packet analysis expertise by running **15 independent analysis modules** against an uploaded capture in seconds. All findings are aggregated and presented in an interactive, web-based multi-tab report viewer accessible from any modern browser.

The application runs locally on any machine — Windows, Linux, or macOS — using a single install script that handles all dependencies automatically.

---

## 2. Why It Exists

Tools like Wireshark are incredibly powerful, but they are inherently time-consuming and require specialized knowledge to filter traffic and interpret protocol-level details effectively. A single capture file can contain millions of packets, and identifying the root cause of a performance issue or a security anomaly demands both expertise and patience.

**TCP Analyzer automates the initial triage layer of packet analysis.** Instead of manually sifting through packets to find anomalies, the utility automatically:

- Identifies issues across security, performance, and protocol dimensions
- Grades each finding by severity (Critical → Info)
- Surfaces the most critical findings at the top of every report
- Reconstructs higher-level objects (HTTP pairs, DNS queries, TLS sessions) from raw packets

A packet capture that typically requires **30+ minutes of manual Wireshark review** can be fully triaged in **under a minute** using TCP Analyzer.

---

## 3. Deployment

TCP Analyzer is fully localized — it runs on the user's own machine with no shared server or central deployment. Each user installs and launches the application independently using the provided install scripts.

| Property | Value |
|---|---|
| **Frontend URL** | `http://localhost:5173` |
| **Backend URL** | `http://localhost:8001` (internal, not exposed) |
| **Supported OS** | Windows 10/11, Linux (Debian, RHEL, Arch, Alpine), macOS |
| **Frontend** | Vite dev server — started by the install script |
| **Backend** | FastAPI / Uvicorn — started by the install script |
The install script (`install.bat` on Windows, `install.sh` on Linux/macOS) handles the full setup and launches both servers. There is no central server to connect to — everything runs on the local machine.

---

## 4. System Architecture

The application follows a standard decoupled frontend/backend architecture with a reverse proxy handling all inbound web traffic.

### Request Flow

```
Browser (http://localhost:5173)
         │
         ▼
   Vite Dev Server (port 5173)
         │
         ├── /          → serves React frontend (hot-reloaded)
         │
         └── /api/*     → proxied to FastAPI backend (port 8001)
                              │
                              ├── Scapy            (packet parsing)
                              ├── 15 Analyzer Modules
                              ├── SQLite           (analysis history)
                              └── Claude (AI chat — in development)
```

### Repository Structure

```
tcp-analyzer/
├── backend/
│   ├── app/
│   │   ├── analyzers/         # 13 analysis modules + orchestration engine
│   │   ├── routes/            # /analyze, /history, /export, /compare, /settings, /ai-chat
│   │   ├── models/            # Pydantic request/response schemas
│   │   ├── main.py            # FastAPI application entry point
│   │   ├── thresholds.py      # Runtime threshold logic
│   │   └── db.py              # SQLite persistence layer
│   ├── data/
│   │   ├── analyses.db        # Auto-created SQLite database
│   │   ├── blocklist.txt      # Local IOC list (one IP per line)
│   │   └── thresholds.json    # User-configurable analysis thresholds
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/             # UploadPage, ReportPage, HistoryPage, ComparePage
│   │   └── components/        # Charts, tables, panels, AIChatPanel
│   └── package.json
├── install.bat                # Windows — automated install + launch
└── install.sh                 # Linux / macOS — automated install + launch
```

### How a PCAP Analysis Works (Internal Flow)

1. User uploads a `.pcap`, `.pcapng`, or `.cap` file via the browser
2. The `POST /api/analyze` endpoint receives the file
3. Scapy parses the raw binary into a packet list
4. The orchestration engine (`analyzers/engine.py`) fans out to all 15 analysis modules concurrently
5. Each module returns a structured result object
6. Results are aggregated, severity-graded, and stored in SQLite
7. The full analysis JSON is returned to the frontend
8. React renders the multi-tab report viewer with the data

---

## 5. Technology Stack

| Component | Technology |
|---|---|
| **Frontend** | React 18, Vite, Recharts, Lucide React |
| **Backend** | Python 3.11, FastAPI, Uvicorn |
| **Packet Parsing** | Scapy |
| **Persistence** | SQLite |
| **Web Server** | Vite Dev Server (local) |
| **Operating System** | Windows 10/11 / Linux / macOS |

---

## 6. Analysis Modules

The backend runs 15 independent modules against every uploaded capture. Results are presented across 15 tabs in the report viewer.

| Tab | Module | Detection and Analysis Scope |
|---|---|---|
| **Overview** | Summary | Severity-graded diagnoses (Critical / High / Medium / Low / Info), total packets, unique IPs, capture duration, protocol distribution |
| **Timeline** | Timeline | Unified chronological event stream aggregated from all modules; ordered by timestamp |
| **Performance** | Performance | TCP handshake latency (avg / P95 / max), retransmissions, zero-window events, application response time, throughput over time |
| **Security** | Security | Port scans, cleartext credential detection, protocol/port mismatches, data exfiltration (>5 MB transfers), DNS tunneling, known scanner signatures |
| **Protocol** | Protocol | TLS handshake failures, DNS NXDOMAIN and SERVFAIL errors, slow DNS resolution, HTTP error rates, TCP RST rates, ICMP unreachable events |
| **Flows** | Flow Analysis | Per-flow metrics (source IP/port, destination IP/port, protocol, packet count, byte count, duration), top talkers by volume |
| **HTTP** | HTTP Objects | Reconstructed HTTP request/response pairs (method, host, path, status code, response size) |
| **DNS** | DNS Map | Per-query DNS records with resolution results, NXDOMAIN/SERVFAIL counts, top queried domains |
| **Fingerprint** | OS Fingerprint | TTL-based OS detection, application banner identification from payload inspection |
| **TLS Deep** | TLS Deep Inspection | JA3 client fingerprinting, weak/deprecated cipher suite detection, SSL3 / TLS 1.0 / TLS 1.1 usage flagging |
| **Geo / IOC** | Geo + IOC | GeoIP enrichment (country, city, ISP) per external IP, local blocklist matching, AbuseIPDB threat scoring (score ≥ 50% flagged) |
| **Beacons** | Beacon Detection | Periodic outbound connection patterns using coefficient of variation — surfaces potential C2 beaconing behavior |
| **RST Forensics** | RST Root Cause | Classifies every TCP reset into one of 10 root cause categories (port closed, firewall drop, TLS rejection, resource exhaustion, application crash, NAT timeout, app refused, middlebox injection, mid-session, and unknown). Each event includes a **summarized evidence chain** of significant steps (SYN, handshake, zero window, HTTP errors) and a **full packet-by-packet trace** of the entire stream, togglable in the UI |
| **MAC Map** | MAC Address Inventory | Maps every MAC address seen in the capture to its associated IPs; resolves hostnames via DHCP option 12, NetBIOS, mDNS, and DNS PTR records; enriches each entry with OUI manufacturer name and packet activity count |
| **Proxy** | Proxy Detection | Identifies proxy involvement via 7 independent signals: HTTP CONNECT tunnels, proxy-specific headers (X-Forwarded-For, Via), SOCKS handshakes, known proxy ports, and third-party IP relaying |

---

## 7. Report Viewer Features

### Diagnoses Panel
A severity-graded findings panel (Critical → Info) is pinned at the top of every report. Findings are generated by all 15 modules and ordered by severity so the most critical issues are immediately visible without navigating individual tabs.

### Export Functionality
Every completed analysis can be exported in three formats:

| Format | Contents |
|---|---|
| **JSON** | Complete structured report — all module results, raw metrics, diagnoses |
| **CSV** | Tabular export covering diagnoses, flow table, beacon candidates, and anomalies |
| **PDF** | Formatted report with cover page, executive summary, and key findings — suitable for sharing or ticketing |

### Analysis History
All completed analyses are persisted to SQLite. The History page provides:
- A searchable list of all past uploads
- One-click access to any previous report
- Per-entry deletion

> **Note:** Raw PCAP binary data is not stored. Only the analysis results (JSON) are persisted.

### Capture Comparison
The Compare page accepts two PCAP files and produces a side-by-side diff across 14 key metrics. This is particularly useful for:
- Before/after comparisons (e.g., before and after a configuration change)
- A/B environment comparisons (e.g., prod vs. staging traffic patterns)

### Configurable Thresholds
The Settings page exposes runtime-tunable thresholds for key analysis parameters — for example, the latency value at which a TCP handshake is flagged as slow, or the retransmission rate that triggers a warning. Threshold changes take effect immediately without requiring a backend restart or redeployment.

---

## 8. Supported File Formats

| Extension | Description |
|---|---|
| `.pcap` | Standard libpcap format — default output of `tcpdump` |
| `.pcapng` | Next-generation PCAP — default format in Wireshark |
| `.cap` | Captured packet file (WinPcap / older tcpdump captures) |

There is no enforced file size limit. Very large captures (>500 MB) will require significant RAM on the server since the entire file is loaded into memory by Scapy for analysis.

---

## 9. User Workflow

1. **Run the install script** (`install.bat` on Windows, `./install.sh` on Linux/macOS) to set up and launch the application — see [Installation](#10-installation). Once both servers are running, **navigate** to `http://localhost:5173` in any modern browser.

2. **Upload** a capture file (`.pcap`, `.pcapng`, or `.cap`) using the drag-and-drop interface or the file picker on the Upload page.

3. *(Optional)* **Provide capture context** — a short description of what was happening when the capture was taken (e.g., "Investigating latency on the ETL pipeline between host A and host B"). This context will be used by the AI analysis feature once it is deployed.

4. **Run the analysis.** The 15 modules execute automatically. Analysis time is typically 5–30 seconds depending on capture size.

5. **Review findings** in the interactive 15-tab report. Start with the Diagnoses panel (Overview tab) for the severity-graded summary, then drill into individual module tabs for detail.

6. *(Optional)* **Export** the report as JSON, CSV, or PDF; **compare** it against another capture; or **return to it later** via the History page.

---

## 10. Installation

### Installing on Any Machine (install scripts)

Two scripts handle the complete setup and launch on any supported platform in a single run. No prior installation of Python, Node.js, or any other dependency is required.

**What the install scripts do (both platforms):**

| Step | Action |
|---|---|
| 1 | Detects and installs missing system dependencies (git, Python 3.9+, Node.js, npm) using the platform's native package manager |
| 2 | Clones the repository (or pulls latest if already present) into `~/tcp-analyzer` |
| 3 | Reads Claude Code `settings.json` to auto-populate Salesforce Bedrock AI gateway credentials |
| 4 | Writes `backend/.env` with credentials |
| 5 | Tests AI gateway reachability and warns if not accessible from the current network |
| 6 | Creates the Python virtual environment in `backend/.venv` and installs all dependencies |
| 7 | Runs `npm install` in `frontend/` |
| 8 | Launches both servers and opens the browser |

The scripts are **idempotent** — re-running on a machine that is already configured will pull the latest code and skip completed steps.

**Windows (Command Prompt — run as Administrator if winget installs are needed):**
```bat
install.bat
```

**Linux / macOS:**
```bash
chmod +x install.sh
./install.sh
```

---

### Run via Docker (No Local Setup Required)

Docker is the simplest way to get TCP Analyzer running on any machine. No Python, Node.js, or git installation required — only Docker Desktop.

Pre-built images are published to GitHub Container Registry (GHCR):

| Image | Purpose |
|---|---|
| `ghcr.io/prabhu-official-ii/tcp-analyzer-backend:latest` | FastAPI + Scapy analysis engine |
| `ghcr.io/prabhu-official-ii/tcp-analyzer-frontend:latest` | React frontend served via nginx |

#### How It Works (Docker Architecture)

```
Browser (http://localhost)
         │
         ▼
   nginx container (port 80)
         │
         ├── /        → serves pre-built React static files
         │
         └── /api/*   → proxies to backend container (port 8000)
                            │
                            ├── Scapy (packet parsing)
                            ├── 15 Analyzer Modules
                            └── SQLite (persisted to ./data/ volume)
```

#### Setup Steps

**Step 1 — Create a `backend.env` file** in your working directory:

```bash
# All fields are optional — leave blank to run without AI Analysis
ANTHROPIC_AUTH_TOKEN=
ANTHROPIC_BEDROCK_BASE_URL=
SSL_CERT_FILE=
ABUSEIPDB_API_KEY=
```

**Step 2 — Create a `docker-compose.yml`** in the same directory:

```yaml
services:
  backend:
    image: ghcr.io/prabhu-official-ii/tcp-analyzer-backend:latest
    env_file: ./backend.env
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  frontend:
    image: ghcr.io/prabhu-official-ii/tcp-analyzer-frontend:latest
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: unless-stopped
```

**Step 3 — Pull and start:**

```bash
docker compose pull
docker compose up -d
```

Open `http://localhost` in your browser.

#### Common Commands

```bash
# Stop containers
docker compose down

# View logs
docker compose logs -f

# Update to the latest images
docker compose pull && docker compose up -d
```

#### Data Persistence

The `./data/` directory is volume-mounted into the backend container. This means:
- `analyses.db` — analysis history survives container restarts and image updates
- `blocklist.txt` — edit this file on the host; the container picks up changes immediately

#### Port Conflict

If port `80` is already in use on your machine, change the `ports` mapping in `docker-compose.yml`:
```yaml
ports:
  - "8080:80"   # access at http://localhost:8080 instead
```

---

### Known Limitation — Windows PATH Refresh After Fresh Python Install

When `install.bat` installs Python via `winget` on a machine with no prior Python installation, the new Python binary is registered in the Windows registry PATH. The currently open `cmd.exe` session does **not** reload the registry PATH automatically.

`install.bat` attempts to compensate by appending the expected Python install path to `%PATH%` in-session. However, if the winget installer places Python at a different path, or the in-session update does not apply in time, the virtual environment creation step (`python -m venv`) will fail.

**Workaround:** Close the Command Prompt after seeing the failure at step 5, open a new `cmd.exe`, and re-run `install.bat`. Python will already be installed; the script will detect it, skip reinstallation, and continue normally.

This is a fundamental Windows shell limitation — the PATH set by an installer is only visible to processes started after the registry write.

---

## 11. Configuration

### Environment Variables (`backend/.env`)

The install scripts auto-generate this file. For manual configuration, create `backend/.env` with the following:

| Variable | Purpose | Required |
|---|---|---|
| `ANTHROPIC_AUTH_TOKEN` | Salesforce Bedrock gateway auth token | For AI Analysis only |
| `ANTHROPIC_BEDROCK_BASE_URL` | Salesforce Bedrock gateway endpoint URL | For AI Analysis only |
| `SSL_CERT_FILE` | Path to Salesforce CA bundle (`.pem`) | For AI Analysis only |
| `ABUSEIPDB_API_KEY` | AbuseIPDB threat intelligence scoring | Optional |

All variables are optional for the core PCAP analysis functionality. The application works fully without them. AI Analysis requires all three Bedrock variables and network access to the gateway endpoint.

> **Note on the AI gateway:** The Salesforce Bedrock gateway is only reachable from machines on the Salesforce corporate network. If the gateway is not reachable, the AI Analysis tab will show a "not available" message — all PCAP analysis features work normally without it.

### Analysis Thresholds (`backend/data/thresholds.json`)

Key analysis thresholds are configurable at runtime via the Settings page in the UI or by editing `thresholds.json` directly. Changes take effect without restarting the backend.

### Local IOC Blocklist (`backend/data/blocklist.txt`)

One IP address per line. Lines beginning with `#` are treated as comments. Any IP in this list will be flagged in the Geo/IOC tab of every report.

```
# Example entries
198.51.100.1
203.0.113.42
```

---

## 12. API Reference

All endpoints are prefixed with `/api`. When running locally, the base URL is `http://localhost:8001/api/...` — or just use the frontend at `http://localhost:5173`, which proxies all `/api/*` requests automatically.

### Analysis

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload a PCAP file (`multipart/form-data`, field: `file`) and run the full 15-module analysis |
| `GET` | `/api/health` | Health check — returns `{"status": "ok"}` |

### History

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/history` | List all saved analyses (metadata only) |
| `GET` | `/api/history/{id}` | Retrieve the full result for a specific analysis |
| `DELETE` | `/api/history/{id}` | Delete a saved analysis |

### Export

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/export/{id}/json` | Download the full analysis as JSON |
| `GET` | `/api/export/{id}/csv` | Download a tabular CSV (diagnoses, flows, beacons, anomalies) |
| `GET` | `/api/export/{id}/pdf` | Download a formatted PDF report |

### Comparison

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/compare` | Upload two captures (`file_a`, `file_b`) and get a side-by-side diff of 14 key metrics |

### Settings

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/settings/thresholds` | Get current threshold configuration |
| `POST` | `/api/settings/thresholds` | Update thresholds (takes effect immediately) |

---

## 13. Roadmap — Embedded AI Analysis

**Status: Under Development**

To further reduce time-to-resolution, an embedded AI chat interface is being integrated into the report viewer. The goal is to allow engineers to query their capture in plain language — without needing to interpret raw module output themselves.

### How It Will Work

After running an analysis, a chat panel will be available within the report. Users can ask questions like:
- *"What is causing the latency spike at 14:32?"*
- *"Is any of this traffic suspicious?"*
- *"Summarize the most critical findings for a ticket."*

The AI model will generate grounded responses that directly reference the utility's own module findings — not raw packets — ensuring answers are relevant and explainable.

### AI Model

The AI chat feature uses Claude via the Salesforce Bedrock gateway. Credentials are auto-configured by the install script from Claude Code `settings.json`. If the gateway is not reachable (e.g., outside the corporate network or Claude Code is not installed), the AI Analysis tab will show a "not available" message — all 15 PCAP analysis modules continue to work normally.

### Data Privacy

No capture data leaves the corporate network. The Bedrock gateway is Salesforce-internal infrastructure — no data reaches any public endpoint.

---

## 14. Maintenance and Ownership

TCP Analyzer is an internally developed and maintained utility.

| | |
|---|---|
| **Owner / Developer** | Penthoi, Prabhu Prasad |
| **Source Repository** | `https://github.com/PRABHU-OFFICIAL-II/tcp-analyzer` |
| **Runs On** | Any machine — Windows, Linux, macOS (see [Installation](#10-installation)) |

For bugs, infrastructure issues, or feature requests, contact Prabhu Prasad directly.

### Generating Test Captures

If you do not have a capture file available, you can generate one using `tcpdump`:

```bash
# 30 seconds of traffic on the default interface
sudo tcpdump -w sample.pcap -G 30 -W 1

# Specific interface
sudo tcpdump -i eth0 -w sample.pcap
```

Or capture from Wireshark and export as `.pcapng`.
