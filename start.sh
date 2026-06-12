#!/usr/bin/env bash
set -e

echo "=== TCP Analyzer (dev mode) ==="

# ── Backend ──────────────────────────────────────────────────────────────────
echo "[1/2] Starting backend..."
cd backend

if [ ! -d ".venv" ]; then
    echo "[backend] venv not found — run ./setup.sh first."
    exit 1
fi

source .venv/bin/activate
uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!
deactivate

# ── Frontend ─────────────────────────────────────────────────────────────────
echo "[2/2] Starting frontend..."
cd ../frontend

if [ ! -d "node_modules" ]; then
    echo "[frontend] node_modules not found — run ./setup.sh first."
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Backend  : http://localhost:8000"
echo "  Frontend : http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
