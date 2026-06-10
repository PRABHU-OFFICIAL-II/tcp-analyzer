@echo off
title TCP Analyzer - Stop

echo Stopping TCP Analyzer servers...

:: Kill uvicorn (backend)
taskkill /f /im uvicorn.exe >nul 2>&1
:: Kill the node process running vite (frontend)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173 " ^| findstr LISTENING') do (
    taskkill /f /pid %%p >nul 2>&1
)

echo [OK] Servers stopped.
timeout /t 2 /nobreak >nul
