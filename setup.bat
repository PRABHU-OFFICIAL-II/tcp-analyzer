@echo off
setlocal enabledelayedexpansion
title TCP Analyzer - Setup

echo ============================================
echo   TCP Analyzer - First-Time Setup
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [OK] %%i

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do echo [OK] Node.js %%i

echo.
echo --- Setting up backend ---
cd backend

:: Remove any broken venv from a previous failed install
if exist ".venv" (
    echo Removing existing virtual environment...
    rmdir /s /q .venv
)

echo Creating Python virtual environment...
python -m venv .venv
if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)

echo Activating venv and installing dependencies...
call .venv\Scripts\activate.bat
pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] pip install failed. See the error above for details.
    pause
    exit /b 1
)
echo [OK] Backend dependencies installed.
call deactivate

echo.
echo --- Setting up frontend ---
cd ..\frontend

echo Installing Node dependencies...
call npm install
if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
)
echo [OK] Frontend dependencies installed.

cd ..
echo.
echo ============================================
echo   Setup complete!
echo   Run start.bat to launch the application.
echo ============================================
echo.
pause
