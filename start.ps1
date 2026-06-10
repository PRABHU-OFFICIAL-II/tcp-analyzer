#Requires -Version 5.1
<#
.SYNOPSIS
    Start TCP Analyzer (backend + frontend) and open the browser.
#>

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host "============================================" -ForegroundColor Blue
Write-Host "  TCP Analyzer                              " -ForegroundColor Blue
Write-Host "============================================" -ForegroundColor Blue

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if (-not (Test-Path "$root\backend\.venv")) {
    Write-Fail "Backend not set up. Run .\setup.ps1 first."
}
if (-not (Test-Path "$root\frontend\node_modules")) {
    Write-Fail "Frontend not set up. Run .\setup.ps1 first."
}

# ── Start backend ─────────────────────────────────────────────────────────────
Write-Step "Starting backend on http://localhost:8000 ..."

$backendArgs = @{
    FilePath         = "cmd.exe"
    ArgumentList     = "/k title TCP Analyzer - Backend && cd /d `"$root\backend`" && call .venv\Scripts\activate.bat && uvicorn app.main:app --reload --port 8000"
    WindowStyle      = "Normal"
}
Start-Process @backendArgs

Start-Sleep -Seconds 2

# ── Start frontend ────────────────────────────────────────────────────────────
Write-Step "Starting frontend on http://localhost:5173 ..."

$frontendArgs = @{
    FilePath         = "cmd.exe"
    ArgumentList     = "/k title TCP Analyzer - Frontend && cd /d `"$root\frontend`" && npm run dev"
    WindowStyle      = "Normal"
}
Start-Process @frontendArgs

# ── Open browser ──────────────────────────────────────────────────────────────
Write-Step "Waiting for servers to be ready..."
$ready = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:5173" -UseBasicParsing -TimeoutSec 1 -ErrorAction SilentlyContinue
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Write-Host "  ." -NoNewline -ForegroundColor Gray
}

Write-Host ""
if ($ready) {
    Write-Ok "Frontend is up. Opening browser..."
    Start-Process "http://localhost:5173"
} else {
    Write-Host "  [INFO] Browser not auto-opened — open http://localhost:5173 manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Servers are running:" -ForegroundColor Green
Write-Host "    Backend:  http://localhost:8000" -ForegroundColor White
Write-Host "    Frontend: http://localhost:5173" -ForegroundColor White
Write-Host ""
Write-Host "  Close the Backend/Frontend windows to stop." -ForegroundColor Gray
Write-Host "  Or run: .\stop.ps1" -ForegroundColor Gray
Write-Host "============================================" -ForegroundColor Green
