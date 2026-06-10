@echo off
setlocal enabledelayedexpansion
title TCP Analyzer

echo ============================================
echo   TCP Analyzer
echo ============================================
echo.

:: Verify setup has been run
if not exist "backend\.venv" (
    echo [ERROR] Backend not set up. Run setup.bat first.
    pause
    exit /b 1
)
if not exist "frontend\node_modules" (
    echo [ERROR] Frontend not set up. Run setup.bat first.
    pause
    exit /b 1
)

echo Starting backend on http://localhost:8000 ...
start "TCP Analyzer - Backend" cmd /k "cd /d %~dp0backend && call .venv\Scripts\activate.bat && uvicorn app.main:app --reload --port 8000"

:: Brief pause so backend window appears first
timeout /t 2 /nobreak >nul

echo Starting frontend on http://localhost:5173 ...
start "TCP Analyzer - Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

:: Wait for frontend dev server to be ready then open browser
timeout /t 4 /nobreak >nul
echo Opening browser...
start "" "http://localhost:5173"

echo.
echo ============================================
echo   Both servers are running.
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo.
echo   Close the Backend and Frontend windows
echo   to stop the servers.
echo ============================================
echo.
pause
