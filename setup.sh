#!/usr/bin/env bash
set -e
echo "=== TCP Analyzer Setup ==="

# ── System dependency installation (RHEL / AlmaLinux / Rocky / CentOS) ──────
if command -v dnf &>/dev/null; then
    echo "[sys] Detected RHEL-family system — installing system dependencies..."

    sudo dnf update -y

    # Python 3.11 with devel headers (needed for C-extension packages like scapy)
    sudo dnf install -y python3.11 python3.11-devel python3-pip

    # libpcap (required by scapy for packet capture)
    sudo dnf install -y libpcap-devel tcpdump

    # Node.js 20 LTS via NodeSource RPM repository
    if ! command -v node &>/dev/null; then
        echo "[sys] Installing Node.js 20 LTS..."
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo dnf install -y nodejs
    else
        echo "[sys] Node.js already installed: $(node --version)"
    fi

    # Nginx
    sudo dnf install -y nginx

    # Utilities
    sudo dnf install -y git rsync zip unzip

    echo "[sys] System dependencies installed."
fi

# ── Backend ──────────────────────────────────────────────────────────────────
echo "[1/2] Setting up backend..."
cd backend

python3.11 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip

# Install torch separately first to allow choosing CPU or CUDA variant.
# Default: CPU-only (safe for any VM). Swap the URL for CUDA if you have a GPU.
if ! python -c "import torch" &>/dev/null; then
    echo "[backend] Installing PyTorch (CPU)..."
    pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
fi

pip install -r requirements.txt
echo "[backend] Python dependencies installed."
deactivate

# ── Frontend ─────────────────────────────────────────────────────────────────
echo "[2/2] Setting up frontend..."
cd ../frontend
npm install
echo "[frontend] Node dependencies installed."

echo ""
echo "Setup complete."
echo "  Development : run ./start.sh"
echo "  Production  : run sudo ./deploy-rhel.sh"
