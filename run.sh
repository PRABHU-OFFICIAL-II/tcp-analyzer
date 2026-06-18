#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

echo "============================================"
echo "  TCP Analyzer - Quick Start"
echo "============================================"
echo ""

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()    { echo "[OK]    $*"; }
info()  { echo "[setup] $*"; }
error() { echo "[ERROR] $*"; exit 1; }

# ── Detect OS and package manager ─────────────────────────────────────────────
install_system_deps() {
    if command -v dnf &>/dev/null; then
        # RHEL / Rocky / AlmaLinux / CentOS
        info "Detected RHEL-family Linux — installing system packages..."
        sudo dnf install -y python3.11 python3.11-devel python3-pip libpcap-devel tcpdump git
        if ! command -v node &>/dev/null; then
            info "Installing Node.js 20 LTS via NodeSource..."
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo dnf install -y nodejs
        fi
    elif command -v apt-get &>/dev/null; then
        # Debian / Ubuntu
        info "Detected Debian-family Linux — installing system packages..."
        sudo apt-get update -y
        sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
            libpcap-dev tcpdump git curl
        if ! command -v node &>/dev/null; then
            info "Installing Node.js 20 LTS via NodeSource..."
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
            sudo apt-get install -y nodejs
        fi
    elif command -v brew &>/dev/null; then
        # macOS
        info "Detected macOS — installing via Homebrew..."
        brew install python@3.11 node libpcap 2>/dev/null || true
    else
        info "Unknown OS — skipping automatic system package install."
        info "Make sure Python 3.10+, Node.js 18+, and libpcap are installed."
    fi
}

# ── Step 1: Python ─────────────────────────────────────────────────────────────
echo "[1/6] Checking Python..."
PYTHON=""
for candidate in python3.11 python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1)
        ok "$version found at $(command -v "$candidate")"
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    info "Python not found — attempting to install system dependencies..."
    install_system_deps
    PYTHON="python3"
    command -v "$PYTHON" &>/dev/null || error "Python install failed. Install Python 3.10+ manually and re-run."
fi

# ── Step 2: Node.js ────────────────────────────────────────────────────────────
echo "[2/6] Checking Node.js..."
if command -v node &>/dev/null; then
    ok "Node.js $(node --version) found."
else
    info "Node.js not found — attempting to install..."
    install_system_deps
    command -v node &>/dev/null || error "Node.js install failed. Install Node.js 18+ manually and re-run."
fi

# ── Step 3: Backend venv ───────────────────────────────────────────────────────
echo "[3/6] Checking backend virtual environment..."
cd "$BACKEND"

if [ ! -d ".venv" ]; then
    info "Creating Python virtual environment..."
    $PYTHON -m venv .venv
    ok "Virtual environment created."
else
    ok "Virtual environment already exists."
fi

source .venv/bin/activate

# ── Step 4: Python dependencies ───────────────────────────────────────────────
echo "[4/6] Checking Python dependencies..."
if ! python -c "import fastapi, uvicorn, scapy, anthropic" &>/dev/null 2>&1; then
    info "Installing Python dependencies (this may take a minute)..."
    pip install --upgrade pip --quiet
    pip install -r requirements.txt
    ok "Python dependencies installed."
else
    ok "Python dependencies already installed."
fi

deactivate

# ── Step 5: Frontend node_modules ─────────────────────────────────────────────
echo "[5/6] Checking frontend dependencies..."
cd "$FRONTEND"

if [ ! -d "node_modules" ]; then
    info "Running npm install (this may take a minute)..."
    npm install
    ok "Frontend dependencies installed."
else
    ok "Frontend dependencies already installed."
fi

# ── Step 6: Load .env and launch ──────────────────────────────────────────────
echo "[6/6] Starting servers..."

cd "$BACKEND"
if [ -f ".env" ]; then
    info "Loading environment variables from backend/.env ..."
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
    ok "Environment loaded."
fi

# Start backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!
deactivate
ok "Backend started (PID $BACKEND_PID) → http://localhost:8000"

# Wait for backend to be ready
sleep 2

# Start frontend
cd "$FRONTEND"
npm run dev &
FRONTEND_PID=$!
ok "Frontend started (PID $FRONTEND_PID) → http://localhost:5173"

# Open browser on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    sleep 3
    open "http://localhost:5173" 2>/dev/null || true
fi

echo ""
echo "============================================"
echo "  TCP Analyzer is running!"
echo ""
echo "  Frontend : http://localhost:5173"
echo "  Backend  : http://localhost:8000"
echo "  API docs : http://localhost:8000/docs"
echo ""
echo "  Press Ctrl+C to stop both servers."
echo "============================================"
echo ""

trap "echo ''; echo 'Stopping...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM
wait
