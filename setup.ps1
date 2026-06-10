#Requires -Version 5.1
<#
.SYNOPSIS
    First-time setup for TCP Analyzer.
#>

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Write-Step($msg)  { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg)  { Write-Host "  [ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host "============================================" -ForegroundColor Blue
Write-Host "  TCP Analyzer - First-Time Setup           " -ForegroundColor Blue
Write-Host "============================================" -ForegroundColor Blue

# ── Check Python ─────────────────────────────────────────────────────────────
Write-Step "Checking prerequisites..."
try {
    $pyVer = python --version 2>&1
    Write-Ok $pyVer
} catch {
    Write-Fail "Python not found. Install from https://python.org (add to PATH)."
}

try {
    $nodeVer = node --version 2>&1
    Write-Ok "Node.js $nodeVer"
} catch {
    Write-Fail "Node.js not found. Install from https://nodejs.org."
}

# ── Backend ───────────────────────────────────────────────────────────────────
Write-Step "Setting up backend..."
Set-Location "$root\backend"

# Always recreate venv to clear any broken state from a prior failed install
if (Test-Path ".venv") {
    Write-Host "  Removing existing virtual environment..." -ForegroundColor Gray
    Remove-Item -Recurse -Force ".venv"
}
Write-Host "  Creating virtual environment..." -ForegroundColor Gray
python -m venv .venv

Write-Host "  Installing Python dependencies..." -ForegroundColor Gray
& ".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
& ".venv\Scripts\python.exe" -m pip install -r requirements.txt
Write-Ok "Backend dependencies installed."

# ── Frontend ──────────────────────────────────────────────────────────────────
Write-Step "Setting up frontend..."
Set-Location "$root\frontend"

Write-Host "  Installing Node dependencies..." -ForegroundColor Gray
npm install
Write-Ok "Frontend dependencies installed."

Set-Location $root

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "  Run: .\start.ps1  to launch the app."    -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
