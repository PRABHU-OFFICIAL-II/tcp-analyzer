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
├── install.bat       # Windows — full install + launch (all-in-one)
└── install.sh        # Linux / macOS — full install + launch (all-in-one)
```

- **Backend** runs on `http://localhost:8001` (falls back to `8002` if occupied)
- **Frontend** runs on `http://localhost:5173`
- Vite proxies all `/api/*` requests to the backend automatically

---

## Deployment Model

**All deployment is handled by the install scripts.** There are no separate setup and start steps, and no platform-level pre-installation required.

`install.bat` (Windows) and `install.sh` (Linux/macOS) are the single entry points. Each script:

1. Detects and installs missing system dependencies (git, Python 3.9+, Node.js, npm, libpcap) using the platform's native package manager — `winget` on Windows, `apt`/`dnf`/`brew`/etc. on Linux/macOS
2. Clones the repository (or pulls latest if already cloned) into `~/tcp-analyzer`
3. Reads Claude Code `settings.json` to auto-configure the Salesforce Bedrock AI gateway credentials
4. Writes `backend/.env` with the credentials (or an empty file if Claude Code is not installed)
5. Tests AI gateway reachability and warns if it is not accessible from the current network
6. Creates the Python virtual environment in `backend/.venv` and installs all Python dependencies
7. Runs `npm install` in `frontend/`
8. Launches both servers and opens the browser

The scripts are idempotent — re-running them on a machine that is already set up will pull the latest code and skip steps that are already complete.

---

## Quick Start

**Windows (Command Prompt — run as Administrator if winget installs are needed):**
```bat
install.bat
```

**Linux / macOS:**
```bash
chmod +x install.sh
./install.sh
```

Then open `http://localhost:5173` in your browser.

To stop: close the terminal windows that opened for the backend and frontend (Windows), or press `Ctrl+C` in the install.sh session (Linux/macOS).

---

## Known Limitation — Windows PATH Refresh After Fresh Python Install

When `install.bat` installs Python via `winget` on a machine that had no Python at all, the new Python binary is added to the system PATH in the Windows registry. The currently open `cmd.exe` window does not reload the registry PATH automatically.

`install.bat` compensates by appending the expected Python path to `%PATH%` in-session, but if the winget installer places Python at a different location than expected, or the in-session PATH update does not take effect in time, the virtual environment creation step (`python -m venv`) will fail.

**Workaround:** Close the `cmd.exe` window after the Python install completes (the script will print an error at step 5 if this happens), open a new Command Prompt, and re-run `install.bat`. The script will detect that Python is now available, skip reinstalling it, and continue from where it left off.

This is a Windows shell limitation — the PATH set by an installer is only visible to processes started after the registry write. There is no reliable way to refresh it in the current shell without spawning a new process.

---

## Prerequisites

No manual pre-installation is required. The install scripts detect and install the following automatically:

| Requirement | Windows | Linux / macOS |
|---|---|---|
| git | `winget install Git.Git` | `apt` / `dnf` / `brew` |
| Python 3.9+ | `winget install Python.Python.3.12` | `apt` / `dnf` / `brew` / `pacman` |
| Node.js 18+ / npm | `winget install OpenJS.NodeJS.LTS` | NodeSource LTS or system package manager |
| libpcap | N/A (not required for file analysis) | `libpcap-dev` / `libpcap-devel` |

> **Windows users**: Npcap or WinPcap is required by Scapy for live packet capture. For PCAP file analysis (the primary use case), it is not required.

If automatic installation fails for any dependency (e.g., corporate policy blocks winget), install that dependency manually and re-run the install script.

---

## Manual Setup (Step by Step)

If you prefer to set things up yourself without the install scripts:

### 1. Clone the repository

```bash
git clone https://github.com/PRABHU-OFFICIAL-II/tcp-analyzer.git
cd tcp-analyzer
```

### 2. Set up the Python virtual environment

```bash
cd backend
python -m venv .venv
```

Activate it:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat
```

You should see `(.venv)` at the start of your terminal prompt.

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

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
uvicorn app.main:app --reload --port 8001
```

The API will be available at `http://localhost:8001`. You can verify it is running at `http://localhost:8001/api/health`.

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
| `ANTHROPIC_AUTH_TOKEN` | Salesforce Bedrock AI gateway auth | AI Analysis tab disabled |
| `ANTHROPIC_BEDROCK_BASE_URL` | Salesforce Bedrock gateway URL | AI Analysis tab disabled |

The install scripts auto-populate `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BEDROCK_BASE_URL` from Claude Code's `settings.json` if Claude Code is installed. `ABUSEIPDB_API_KEY` must be set manually.

**Windows (Command Prompt):**
```bat
set ABUSEIPDB_API_KEY=your_key_here
uvicorn app.main:app --reload --port 8001
```

**macOS / Linux:**
```bash
export ABUSEIPDB_API_KEY=your_key_here
uvicorn app.main:app --reload --port 8001
```

You can get a free AbuseIPDB API key at [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api).

---

## AI Analysis

The AI Analysis tab uses the Salesforce-deployed Claude model via AWS Bedrock. It is available only on machines that:

1. Have Claude Code installed and configured with a valid `ANTHROPIC_AUTH_TOKEN`
2. Can reach the `ANTHROPIC_BEDROCK_BASE_URL` endpoint (i.e., are on the Salesforce corporate network or VPN)

If either condition is not met, the AI Analysis tab shows a "not available on this deployment" message. All other PCAP analysis features (the 13 modules, export, comparison, history) work normally without AI access.

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

**`install.bat` fails at step 5 (venv creation) on a fresh Windows machine**
Python was just installed by winget and the current `cmd.exe` session did not pick up the new PATH. Close the window, open a new Command Prompt, and re-run `install.bat`. See [Known Limitation — Windows PATH Refresh](#known-limitation--windows-path-refresh-after-fresh-python-install) above.

**`ModuleNotFoundError: No module named 'scapy'`**
The virtual environment is not active. Run the activate command for your OS (see Manual Setup above) and try again.

**`ERROR: [WinError 5] Access is denied` (Windows, Scapy)**
Run the terminal as Administrator, or install Npcap from [https://npcap.com](https://npcap.com).

**Frontend shows "Network Error" or blank report**
The backend is not running or is on a different port. Make sure `uvicorn` is running on port 8001 (or 8002) before starting the frontend.

**`address already in use` on port 8001 or 5173**
`install.bat` automatically falls back to port 8002 if 8001 is occupied. To free the port manually on Windows: `netstat -ano | findstr :8001` then `taskkill /PID <pid> /F`. On Linux/macOS: `kill $(lsof -t -i:8001)`.

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
