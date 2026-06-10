#Requires -Version 5.1
<#
.SYNOPSIS
    Stop all TCP Analyzer server processes.
#>

Write-Host "Stopping TCP Analyzer servers..." -ForegroundColor Cyan

# Stop uvicorn (backend)
Get-Process -Name "uvicorn" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force
    Write-Host "  [OK] Stopped backend (uvicorn PID $($_.Id))" -ForegroundColor Green
}

# Stop node process listening on port 5173 (Vite frontend)
$port5173 = netstat -ano | Select-String ":5173 " | Select-String "LISTENING"
if ($port5173) {
    $pid5173 = ($port5173 -split "\s+")[-1]
    try {
        Stop-Process -Id $pid5173 -Force
        Write-Host "  [OK] Stopped frontend (node PID $pid5173)" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Could not stop PID $pid5173 — may already be stopped." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] No process found on port 5173." -ForegroundColor Gray
}

Write-Host "`nDone." -ForegroundColor Green
