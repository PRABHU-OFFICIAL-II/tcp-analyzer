#!/usr/bin/env bash
# ==============================================================
#  TCP Analyzer - Linux / macOS installer + launcher
#  Reads Claude Code settings.json to auto-configure the
#  Salesforce Bedrock gateway credentials.
# ==============================================================

set -euo pipefail

REPO_URL="https://github.com/PRABHU-OFFICIAL-II/tcp-analyzer.git"
APP_DIR="$HOME/tcp-analyzer"

# ── Colours ────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}  ${1}${RESET}"; }
success() { echo -e "${GREEN}  ✓ ${1}${RESET}"; }
warn()    { echo -e "${YELLOW}  ⚠ ${1}${RESET}"; }
error()   { echo -e "${RED}  ✗ ${1}${RESET}" >&2; exit 1; }
banner()  { echo -e "\n${BOLD}[${1}] ${2}${RESET}"; }

echo -e "\n${BOLD} =========================================================="
echo   "  TCP Analyzer - Setup & Launch"
echo -e " ==========================================================${RESET}\n"

# ── 1. Detect OS + install system packages ─────────────────────
banner "1/7" "Installing system dependencies"

DISTRO=""
if [[ "$(uname)" == "Darwin" ]]; then
    DISTRO="macos"
elif [[ -f /etc/os-release ]]; then
    # Parse /etc/os-release for accurate distro detection
    ID=$(grep -E "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
    ID_LIKE=$(grep -E "^ID_LIKE=" /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]' || echo "")
    case "$ID" in
        rhel|centos|fedora|rocky|almalinux|ol|scientific|amzn)
            DISTRO="rhel" ;;
        ubuntu|debian|linuxmint|pop|kali|raspbian|elementary)
            DISTRO="debian" ;;
        opensuse*|sles|sled)
            DISTRO="suse" ;;
        arch|manjaro|endeavouros)
            DISTRO="arch" ;;
        alpine)
            DISTRO="alpine" ;;
        *)
            # Fall back to ID_LIKE
            case "$ID_LIKE" in
                *rhel*|*centos*|*fedora*)   DISTRO="rhel" ;;
                *debian*|*ubuntu*)          DISTRO="debian" ;;
                *suse*)                     DISTRO="suse" ;;
                *arch*)                     DISTRO="arch" ;;
                *)
                    # Last resort: check for well-known files
                    [[ -f /etc/redhat-release ]] && DISTRO="rhel"
                    [[ -f /etc/debian_version ]] && DISTRO="debian"
                    ;;
            esac
            ;;
    esac
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="rhel"
elif [[ -f /etc/debian_version ]]; then
    DISTRO="debian"
fi

info "Detected OS: ${DISTRO:-unknown} ($(uname -s) $(uname -m))"

install_pkg() {
    case "$DISTRO" in
        rhel)
            # RHEL / CentOS / Fedora / Rocky / AlmaLinux / Amazon Linux
            if command -v dnf &>/dev/null; then
                sudo dnf install -y "$@" 2>/dev/null \
                || warn "Could not install $* via dnf"
            else
                sudo yum install -y "$@" 2>/dev/null \
                || warn "Could not install $* via yum"
            fi
            ;;
        debian)
            # Debian / Ubuntu / Mint / Kali / Raspbian
            sudo apt-get update -qq 2>/dev/null || true
            sudo apt-get install -y -qq "$@" \
            || warn "Could not install $* via apt-get"
            ;;
        suse)
            # openSUSE / SLES
            sudo zypper install -y "$@" 2>/dev/null \
            || warn "Could not install $* via zypper"
            ;;
        arch)
            # Arch / Manjaro / EndeavourOS
            sudo pacman -S --noconfirm "$@" 2>/dev/null \
            || warn "Could not install $* via pacman"
            ;;
        alpine)
            sudo apk add --no-cache "$@" 2>/dev/null \
            || warn "Could not install $* via apk"
            ;;
        macos)
            if command -v brew &>/dev/null; then
                brew install "$@" 2>/dev/null \
                || warn "Could not install $* via brew"
            else
                warn "Homebrew not found. Install from https://brew.sh then re-run."
            fi
            ;;
        *)
            warn "Unknown distro — cannot auto-install: $*"
            warn "Please install $* manually and re-run this script."
            ;;
    esac
}

# Map package names that differ by distro
pkg_python3_venv() {
    case "$DISTRO" in
        rhel)   echo "python3-venv" ;;
        debian) echo "python3-venv" ;;
        suse)   echo "python3-virtualenv" ;;
        arch)   echo "python" ;;      # venv is included
        alpine) echo "py3-virtualenv" ;;
        macos)  echo "" ;;            # venv built-in
        *)      echo "python3-venv" ;;
    esac
}

pkg_libpcap_dev() {
    case "$DISTRO" in
        rhel)   echo "libpcap libpcap-devel" ;;
        debian) echo "libpcap-dev" ;;
        suse)   echo "libpcap-devel" ;;
        arch)   echo "libpcap" ;;
        alpine) echo "libpcap-dev" ;;
        macos)  echo "" ;;            # libpcap is built-in
        *)      echo "libpcap-dev" ;;
    esac
}

# Ensure git
if ! command -v git &>/dev/null; then
    info "Installing git..."
    install_pkg git
fi
command -v git &>/dev/null || error "git is required but could not be installed."

# Ensure Python 3.9+
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(sys.version_info >= (3,9))" 2>/dev/null || echo "False")
        if [[ "$VER" == "True" ]]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    info "Installing Python 3..."
    case "$DISTRO" in
        rhel)    install_pkg python3 python3-pip python3-venv ;;
        debian)  install_pkg python3 python3-pip python3-venv python3-dev build-essential ;;
        suse)    install_pkg python3 python3-pip python3-virtualenv python3-devel ;;
        arch)    install_pkg python python-pip ;;
        alpine)  install_pkg python3 py3-pip py3-virtualenv ;;
        macos)   install_pkg python@3 ;;
    esac
    PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || "")
    [[ -z "$PYTHON" ]] && error "Python 3.9+ is required but could not be installed."
fi
success "Python: $($PYTHON --version)"

# Ensure pip
"$PYTHON" -m pip --version &>/dev/null || {
    info "Installing pip..."
    case "$DISTRO" in
        rhel)   install_pkg python3-pip ;;
        debian) install_pkg python3-pip ;;
        suse)   install_pkg python3-pip ;;
        arch)   install_pkg python-pip ;;
        alpine) install_pkg py3-pip ;;
        macos)  "$PYTHON" -m ensurepip --upgrade 2>/dev/null || true ;;
    esac
}

# Ensure venv
"$PYTHON" -m venv --help &>/dev/null 2>&1 || {
    info "Installing python3-venv..."
    VENV_PKG=$(pkg_python3_venv)
    [[ -n "$VENV_PKG" ]] && install_pkg $VENV_PKG
}

# Ensure Node / npm
if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
    info "Installing Node.js..."
    case "$DISTRO" in
        rhel)
            sudo dnf module install -y nodejs:20 2>/dev/null \
            || sudo dnf install -y nodejs npm 2>/dev/null \
            || { install_pkg nodejs npm; } \
            || warn "Could not install Node.js"
            ;;
        debian)
            # NodeSource provides a recent LTS release
            if command -v curl &>/dev/null; then
                curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null \
                && sudo apt-get install -y nodejs 2>/dev/null \
                || install_pkg nodejs npm
            else
                install_pkg nodejs npm
            fi
            ;;
        suse)    install_pkg nodejs npm ;;
        arch)    install_pkg nodejs npm ;;
        alpine)  install_pkg nodejs npm ;;
        macos)   install_pkg node ;;
    esac
fi
command -v node &>/dev/null || error "Node.js is required but could not be installed."
success "Node: $(node --version), npm: $(npm --version)"

# libpcap (needed by Scapy) — best-effort, non-fatal
PCAP_PKGS=$(pkg_libpcap_dev)
if [[ -n "$PCAP_PKGS" ]]; then
    install_pkg $PCAP_PKGS 2>/dev/null || true
fi

# ── 2. Clone or update repo ────────────────────────────────────
banner "2/7" "Cloning / updating repository"

if [[ -d "$APP_DIR/.git" ]]; then
    info "Repository already exists at $APP_DIR — pulling latest..."
    cd "$APP_DIR"
    git pull --ff-only || warn "git pull failed — continuing with existing code."
else
    info "Cloning into $APP_DIR..."
    git clone "$REPO_URL" "$APP_DIR"
    cd "$APP_DIR"
fi
success "Repository ready at $APP_DIR"

BACKEND_DIR="$APP_DIR/backend"
FRONTEND_DIR="$APP_DIR/frontend"

# ── 3. Read Claude Code settings.json ──────────────────────────
banner "3/7" "Reading Claude Code settings"

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
AUTH_TOKEN=""
BEDROCK_URL=""
SSL_CERT=""

if [[ -f "$CLAUDE_SETTINGS" ]]; then
    PARSED=$("$PYTHON" -c "
import json, sys
try:
    d = json.load(open('$CLAUDE_SETTINGS'))
    env = d.get('env', {})
    print('AUTH=' + env.get('ANTHROPIC_AUTH_TOKEN', ''))
    print('URL='  + env.get('ANTHROPIC_BEDROCK_BASE_URL', ''))
    print('CERT=' + env.get('NODE_EXTRA_CA_CERTS', ''))
except Exception as e:
    print('ERR=' + str(e))
" 2>/dev/null || echo "")

    while IFS= read -r line; do
        case "$line" in
            AUTH=*) AUTH_TOKEN="${line#AUTH=}" ;;
            URL=*)  BEDROCK_URL="${line#URL=}" ;;
            CERT=*) SSL_CERT="${line#CERT=}" ;;
            ERR=*)  warn "Could not parse settings.json: ${line#ERR=}" ;;
        esac
    done <<< "$PARSED"

    if [[ -n "$AUTH_TOKEN" ]]; then
        success "Credentials found in Claude settings."
    else
        warn "ANTHROPIC_AUTH_TOKEN not found in settings.json — AI chat will be disabled."
    fi
else
    warn "Claude Code settings not found at $CLAUDE_SETTINGS"
    warn "This is expected on Linux VMs — Claude Code is typically not installed there."
    info "The app will run normally. All PCAP analysis features work without AI chat."
    info "If Salesforce grants AI gateway access to this VM later, manually create:"
    info "  $BACKEND_DIR/.env"
    info "  with ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BEDROCK_BASE_URL values."
fi

# ── 4. Write backend/.env ──────────────────────────────────────
banner "4/7" "Writing backend/.env"

ENV_FILE="$BACKEND_DIR/.env"
{
    echo "# Auto-generated by install.sh — do not commit this file"
    [[ -n "$AUTH_TOKEN"  ]] && echo "ANTHROPIC_AUTH_TOKEN=$AUTH_TOKEN"
    [[ -n "$BEDROCK_URL" ]] && echo "ANTHROPIC_BEDROCK_BASE_URL=$BEDROCK_URL"
    [[ -n "$SSL_CERT"    ]] && echo "SSL_CERT_FILE=$SSL_CERT"
} > "$ENV_FILE"
success "Written to $ENV_FILE"

# Connectivity check — warn if Bedrock gateway is unreachable
if [[ -n "$BEDROCK_URL" ]]; then
    info "Testing gateway connectivity (5s timeout)..."
    REACHABLE=$("$PYTHON" -c "
import urllib.request, ssl, os, sys
url  = '$BEDROCK_URL'
cert = '$SSL_CERT'
try:
    ctx = ssl.create_default_context()
    if cert and os.path.exists(cert):
        ctx.load_verify_locations(cert)
    urllib.request.urlopen(url, timeout=5, context=ctx)
    print('YES')
except Exception as e:
    msg = str(e).lower()
    print('NO:' + str(e))
" 2>/dev/null || echo "NO:check failed")

    if [[ "$REACHABLE" == YES* ]]; then
        success "Salesforce AI gateway is reachable — AI chat will be fully functional."
    else
        echo ""
        warn "*** NOTICE ***"
        warn "The Salesforce AI gateway is NOT reachable from this machine."
        warn "Reason: ${REACHABLE#NO:}"
        warn "This is expected on VMs / machines outside the Salesforce"
        warn "corporate network. The AI chat tab will show a friendly"
        warn "'not available on this deployment' message — all PCAP"
        warn "analysis features will still work normally."
        warn "***************"
        echo ""
    fi
fi

# ── 5. Python venv + backend deps ──────────────────────────────
banner "5/7" "Installing Python dependencies"

VENV_DIR="$BACKEND_DIR/.venv"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    info "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Upgrading pip..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet

info "Installing requirements..."
"$VENV_PIP" install -r "$BACKEND_DIR/requirements.txt" --quiet
success "Python dependencies installed."

# ── 6. Node / frontend deps ────────────────────────────────────
banner "6/7" "Installing Node.js dependencies"

cd "$FRONTEND_DIR"
npm install --silent
success "Node dependencies installed."

# ── 7. Launch both servers ─────────────────────────────────────
banner "7/7" "Starting servers"

# Pick a free backend port
BACKEND_PORT=8001
if ss -tlnp 2>/dev/null | grep -q ":8001 " || \
   netstat -tlnp 2>/dev/null | grep -q ":8001 "; then
    BACKEND_PORT=8002
    warn "Port 8001 in use — using $BACKEND_PORT for backend."

    # Update the vite proxy port
    "$PYTHON" -c "
import re, pathlib
p = pathlib.Path('$FRONTEND_DIR/vite.config.js')
t = p.read_text()
t2 = re.sub(r'http://localhost:\d+', 'http://localhost:$BACKEND_PORT', t)
if t != t2:
    p.write_text(t2)
    print('  Updated vite proxy to port $BACKEND_PORT')
" 2>/dev/null || true
fi

echo ""
echo -e "${BOLD}  Backend : http://localhost:${BACKEND_PORT}${RESET}"
echo -e "${BOLD}  Frontend: http://localhost:5173${RESET}"
echo ""
echo -e "  ${YELLOW}Press Ctrl+C to stop both servers.${RESET}"
echo ""

# Launch backend in background
cd "$BACKEND_DIR"
"$VENV_PYTHON" -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "$BACKEND_PORT" \
    --reload &
BACKEND_PID=$!

# Wait for backend to be ready
sleep 3

# Launch frontend in background
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

# Attempt to open browser (best-effort)
sleep 3
if command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:5173" &>/dev/null &
elif command -v open &>/dev/null; then
    open "http://localhost:5173" &
fi

# Trap Ctrl+C — kill both servers cleanly
cleanup() {
    echo ""
    info "Shutting down..."
    kill "$BACKEND_PID"  2>/dev/null || true
    kill "$FRONTEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID"  2>/dev/null || true
    wait "$FRONTEND_PID" 2>/dev/null || true
    success "Stopped. Goodbye."
    exit 0
}
trap cleanup INT TERM

# Keep running until user hits Ctrl+C
success "Both servers running. Open http://localhost:5173 in your browser."
wait
