# TCP Analyzer

A comprehensive network traffic analysis platform that processes PCAP captures and generates detailed security, performance, and protocol insights through an interactive web UI.

---

## What It Does

Upload a `.pcap`, `.pcapng`, or `.cap` file and the analyzer runs 13 independent analysis modules on your capture:

| Module | What It Detects |
|---|---|
| **Performance** | Retransmissions, TCP zero window, handshake latency, application response time, throughput |
| **Security** | Port scans, cleartext credentials, protocol/port mismatches, data exfiltration (>5 MB), DNS tunneling |
| **Protocol** | TLS handshake failures, DNS errors (NXDOMAIN, slow resolves), HTTP error rates, connection reset rates |
| **Flow** | Per-flow metrics (src/dst, protocol, packets, bytes, duration), top talkers |
| **Beacon** | Periodic outbound connection patterns (C2 / beaconing detection via coefficient of variation) |
| **TLS Deep** | JA3 fingerprinting, cipher suite classification, deprecated version detection (SSL3, TLS 1.0/1.1) |
| **Fingerprint** | TTL-based OS detection, application banner detection |
| **Geo** | GeoIP lookup (country, city, ISP) via ip-api.com |
| **IOC** | Local blocklist matching + AbuseIPDB API integration (score ≥ 50% flagged) |
| **ARP** | ARP spoofing detection (same IP seen with multiple MACs) |
| **RST Forensics** | Root cause classification for every TCP reset (9 categories: port closed, firewall, TLS rejection, resource exhaustion, app crash, NAT timeout, etc.) |

Results are shown in a 10-tab report viewer. You can also compare two captures side-by-side and export reports as JSON, CSV, or PDF.

---

## Architecture

```
tcp-analyzer/
├── backend/          # FastAPI + Scapy — analysis engine and REST API
│   ├── app/
│   │   ├── analyzers/    # 13 analysis modules + orchestration engine
│   │   ├── routes/       # /analyze, /history, /export, /compare
│   │   ├── models/       # Pydantic schemas
│   │   ├── main.py       # FastAPI app entry point
│   │   └── db.py         # SQLite persistence
│   ├── data/
│   │   ├── analyses.db   # Auto-created SQLite database
│   │   └── blocklist.txt # Local IOC list (one IP per line)
│   └── requirements.txt
├── frontend/         # React + Vite — upload, report viewer, history, compare
│   ├── src/
│   │   ├── pages/        # UploadPage, ReportPage, HistoryPage, ComparePage
│   │   └── components/   # Charts, tables, panels
│   └── package.json
├── setup.bat / setup.sh / setup.ps1   # First-time environment setup
└── start.bat / start.sh / start.ps1   # Launch both servers
```

- **Backend** runs on `http://localhost:8000`
- **Frontend** runs on `http://localhost:5173`
- Vite proxies all `/api/*` requests to the backend automatically

---

## Prerequisites

| Requirement | Minimum Version | Check |
|---|---|---|
| Python | 3.10+ | `python --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |

> **Windows users**: Npcap or WinPcap is required by Scapy for live capture. For PCAP file analysis only, it is not required.

---

## Quick Start (Automated)

Setup scripts handle the virtual environment, pip install, and npm install for you.

**Windows (Command Prompt):**
```bat
setup.bat
start.bat
```

**Windows (PowerShell):**
```powershell
.\setup.ps1
.\start.ps1
```

**macOS / Linux:**
```bash
chmod +x setup.sh start.sh
./setup.sh
./start.sh
```

Then open `http://localhost:5173` in your browser.

To stop: run `stop.bat` / `stop.ps1` on Windows, or press `Ctrl+C` on macOS/Linux.

---

## Manual Setup (Step by Step)

If you prefer to set things up yourself, or the scripts don't work in your environment:

### 1. Clone the repository

```bash
git clone <repo-url>
cd tcp-analyzer
```

### 2. Set up the Python virtual environment

```bash
cd backend

# Create the virtual environment
python -m venv .venv
```

Activate it:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

You should see `(.venv)` at the start of your terminal prompt.

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---|---|
| `fastapi` | Web framework |
| `uvicorn[standard]` | ASGI server |
| `scapy` | Packet parsing and analysis |
| `python-multipart` | File upload handling |
| `fpdf2` | PDF report generation |

### 4. Install frontend dependencies

Open a second terminal:

```bash
cd frontend
npm install
```

### 5. Start the backend

From the `backend/` directory with the virtual environment active:

```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. You can verify it is running at `http://localhost:8000/api/health`.

### 6. Start the frontend

From the `frontend/` directory:

```bash
npm run dev
```

The UI will be available at `http://localhost:5173`.

---

## Environment Variables (Optional)

These are set before starting the backend. None are required — the app works without them.

| Variable | Purpose | Default behavior |
|---|---|---|
| `ABUSEIPDB_API_KEY` | Enables AbuseIPDB threat intelligence scoring | Falls back to local blocklist only |

**Windows (Command Prompt):**
```bat
set ABUSEIPDB_API_KEY=your_key_here
uvicorn app.main:app --reload --port 8000
```

**macOS / Linux:**
```bash
export ABUSEIPDB_API_KEY=your_key_here
uvicorn app.main:app --reload --port 8000
```

You can get a free AbuseIPDB API key at [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api).

---

## Adding IOCs to the Local Blocklist

Edit `backend/data/blocklist.txt`. One IP address per line. Lines starting with `#` are treated as comments.

```
# Known malicious IPs
198.51.100.1
203.0.113.42
```

Any IP in this list will be flagged in the IOC tab of the report.

---

## API Reference

All endpoints are prefixed with `/api`.

### Analysis

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload a PCAP file (multipart form, field: `file`) and run full analysis |
| `GET` | `/api/health` | Health check |

### History

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/history` | List all saved analyses |
| `GET` | `/api/history/{id}` | Retrieve a specific report |
| `DELETE` | `/api/history/{id}` | Delete an analysis |

### Export

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/export/{id}/json` | Full report as JSON |
| `GET` | `/api/export/{id}/csv` | Tabular export (diagnoses, anomalies, flows, beacons) |
| `GET` | `/api/export/{id}/pdf` | Formatted PDF with cover page and key findings |

### Comparison

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/compare` | Upload two PCAPs (`file_a`, `file_b`) and get a side-by-side diff of 14 metrics |

---

## Supported File Formats

| Extension | Description |
|---|---|
| `.pcap` | Standard libpcap format |
| `.pcapng` | Next-generation PCAP (Wireshark default) |
| `.cap` | Captured packet file (WinPcap / tcpdump) |

There is no enforced file size limit, but very large captures (>500 MB) will require significant RAM since the entire file is loaded into memory for analysis.

---

## Generating Test Captures

If you don't have a PCAP handy, you can generate one with `tcpdump` or Wireshark:

```bash
# Capture 30 seconds of traffic on the default interface
sudo tcpdump -w sample.pcap -G 30 -W 1

# Or capture a specific interface
sudo tcpdump -i eth0 -w sample.pcap
```

Place test files in `sample_pcaps/` for convenience.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'scapy'`**
The virtual environment is not active. Run the activate command for your OS (see step 2 above) and try again.

**`ERROR: [WinError 5] Access is denied` (Windows, Scapy)**
Run the terminal as Administrator, or install Npcap from [https://npcap.com](https://npcap.com).

**Frontend shows "Network Error" or blank report**
The backend is not running or is on a different port. Make sure `uvicorn` is running on port 8000 before starting the frontend.

**`address already in use` on port 8000 or 5173**
Another process is using the port. On Windows, run `stop.bat` to kill previous instances. On Linux/macOS: `kill $(lsof -t -i:8000)`.

**PowerShell execution policy error**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## Tech Stack

**Backend**
- Python 3.10+
- FastAPI — REST API framework
- Uvicorn — ASGI server
- Scapy — Packet parsing and protocol dissection
- fpdf2 — PDF generation
- SQLite — Analysis history persistence

**Frontend**
- React 18
- Vite — Dev server and bundler
- Recharts — Throughput and geo distribution charts
- Lucide React — Icons
