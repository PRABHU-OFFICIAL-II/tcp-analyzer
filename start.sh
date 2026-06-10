#!/usr/bin/env bash
set -e

echo "=== TCP Analyzer ==="

# Backend
echo "[1/2] Starting backend..."
cd backend
if [ ! -d ".venv" ]; then
  python -m venv .venv
  .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
  pip install -r requirements.txt
else
  .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
fi
uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!

# Frontend
echo "[2/2] Starting frontend..."
cd ../frontend
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Backend:  http://localhost:8000"
echo "  Frontend: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
