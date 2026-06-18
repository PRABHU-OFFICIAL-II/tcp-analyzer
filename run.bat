@echo off
setlocal enabledelayedexpansion
title TCP Analyzer

echo ============================================
echo   TCP Analyzer - Quick Start
echo ============================================
echo.

set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "FRONTEND=%ROOT%frontend"

:: ── Check Python ─────────────────────────────────────────────────────────────
echo [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo         Install Python 3.10+ from https://python.org and re-run this script.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [OK] %%i found.

:: ── Check Node.js ────────────────────────────────────────────────────────────
echo [2/6] Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found.
    echo         Install Node.js 18+ from https://nodejs.org and re-run this script.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do echo [OK] Node.js %%i found.

:: ── Backend venv + dependencies ──────────────────────────────────────────────
echo [3/6] Checking backend virtual environment...
cd /d "%BACKEND%"

if not exist ".venv" (
    echo [setup] Creating Python virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

echo [4/6] Checking Python dependencies...
call .venv\Scripts\activate.bat

:: Check if key packages are installed by testing a fast import
python -c "import fastapi, uvicorn, scapy, anthropic" >nul 2>&1
if errorlevel 1 (
    echo [setup] Installing Python dependencies ^(this may take a minute^)...
    pip install --upgrade pip --quiet
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] pip install failed. See the error above.
        pause
        exit /b 1
    )
    echo [OK] Python dependencies installed.
) else (
    echo [OK] Python dependencies already installed.
)

:: ── Frontend node_modules ─────────────────────────────────────────────────────
echo [5/6] Checking frontend dependencies...
cd /d "%FRONTEND%"

if not exist "node_modules" (
    echo [setup] Running npm install ^(this may take a minute^)...
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
    echo [OK] Frontend dependencies installed.
) else (
    echo [OK] Frontend dependencies already installed.
)

:: ── Load .env if present ──────────────────────────────────────────────────────
cd /d "%BACKEND%"
if exist ".env" (
    echo [env] Loading environment variables from backend\.env ...
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" if not "%%A:~0,1%"=="#" (
            set "%%A=%%B"
        )
    )
    echo [OK] Environment loaded.
)

:: ── Launch servers ────────────────────────────────────────────────────────────
echo [6/6] Starting servers...
echo.

start "TCP Analyzer - Backend" cmd /k "cd /d "%BACKEND%" && call .venv\Scripts\activate.bat && uvicorn app.main:app --reload --port 8001"

timeout /t 3 /nobreak >nul

start "TCP Analyzer - Frontend" cmd /k "cd /d "%FRONTEND%" && npm run dev"

timeout /t 5 /nobreak >nul

echo Opening browser...
start "" "http://localhost:5173"

echo.
echo ============================================
echo   TCP Analyzer is running!
echo.
echo   Frontend : http://localhost:5173
echo   Backend  : http://localhost:8000
echo   API docs : http://localhost:8000/docs
echo.
echo   Close the Backend and Frontend windows
echo   to stop the servers.
echo ============================================
echo.
pause
