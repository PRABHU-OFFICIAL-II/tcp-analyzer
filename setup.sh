#!/usr/bin/env bash
set -e
echo "=== Setting up TCP Analyzer ==="

# Backend
cd backend
python -m venv .venv
.venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
pip install -r requirements.txt
echo "Backend deps installed."

# Frontend
cd ../frontend
npm install
echo "Frontend deps installed."

echo ""
echo "Setup complete. Run ./start.sh to launch."
