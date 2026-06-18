@echo off
setlocal EnableDelayedExpansion
title TCP Analyzer - Setup and Launch

echo.
echo  ==========================================================
echo   TCP Analyzer - Setup ^& Launch (Windows)
echo  ==========================================================
echo.

set "REPO_URL=https://github.com/PRABHU-OFFICIAL-II/tcp-analyzer.git"
set "APP_DIR=%USERPROFILE%\tcp-analyzer"
set "BACKEND_DIR=%APP_DIR%\backend"
set "FRONTEND_DIR=%APP_DIR%\frontend"
set "TMP_PY=%TEMP%\tcpanalyzer_helper.py"

:: ── 1. Auto-install prerequisites via winget ───────────────
echo [1/7] Checking and installing prerequisites...

:: Git
where git >nul 2>&1
if errorlevel 1 (
    echo  git not found - installing via winget...
    winget install --id Git.Git -e --source winget --silent --accept-package-agreements --accept-source-agreements
    set "PATH=%PATH%;C:\Program Files\Git\cmd"
)
where git >nul 2>&1 || ( echo  ERROR: git install failed. Please restart this script. & pause & exit /b 1 )
echo  git: OK

:: Python - find a 3.9+ interpreter
set "PYTHON="
for %%C in (python python3) do (
    if "!PYTHON!"=="" (
        where %%C >nul 2>&1
        if not errorlevel 1 (
            for /f "delims=" %%V in ('%%C -c "import sys; print(1 if sys.version_info>=(3,9) else 0)" 2^>nul') do (
                if "%%V"=="1" set "PYTHON=%%C"
            )
        )
    )
)
if "!PYTHON!"=="" (
    echo  Python 3.9+ not found - installing via winget...
    winget install --id Python.Python.3.12 -e --source winget --silent --accept-package-agreements --accept-source-agreements
    set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
    for %%C in (python python3) do (
        if "!PYTHON!"=="" ( where %%C >nul 2>&1 && set "PYTHON=%%C" )
    )
)
if "!PYTHON!"=="" ( echo  ERROR: Python install failed. Restart this script after install completes. & pause & exit /b 1 )
echo  Python: OK  (!PYTHON!)

:: Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo  Node.js not found - installing via winget...
    winget install --id OpenJS.NodeJS.LTS -e --source winget --silent --accept-package-agreements --accept-source-agreements
    set "PATH=%PATH%;C:\Program Files\nodejs"
)
where node >nul 2>&1 || ( echo  ERROR: Node.js install failed. Restart this script. & pause & exit /b 1 )
where npm  >nul 2>&1 || ( echo  ERROR: npm not found after Node install. Restart this script. & pause & exit /b 1 )
echo  Node.js / npm: OK

:: ── 2. Clone or update repo ────────────────────────────────
echo.
echo [2/7] Cloning / updating repository...

if exist "%APP_DIR%\.git" (
    echo  Repo exists at %APP_DIR% - pulling latest changes...
    cd /d "%APP_DIR%"
    git pull --ff-only 2>nul || echo  WARNING: git pull failed - continuing with existing code.
) else (
    echo  Cloning into %APP_DIR%...
    git clone "%REPO_URL%" "%APP_DIR%"
    if errorlevel 1 ( echo  ERROR: git clone failed. & pause & exit /b 1 )
    cd /d "%APP_DIR%"
)
echo  Repository ready.

:: ── 3. Read Claude settings.json ───────────────────────────
echo.
echo [3/7] Reading Claude Code settings...

set "CLAUDE_SETTINGS=%USERPROFILE%\.claude\settings.json"
set "AUTH_TOKEN="
set "BEDROCK_URL="
set "SSL_CERT="

if exist "%CLAUDE_SETTINGS%" (

    :: Write helper script to a temp file to avoid cmd parenthesis parsing issues
    (
        echo import json, sys
        echo try:
        echo     d = json.load(open(sys.argv[1]))
        echo     env = d.get('env', {})
        echo     print('AUTH=' + env.get('ANTHROPIC_AUTH_TOKEN', ''))
        echo     print('URL='  + env.get('ANTHROPIC_BEDROCK_BASE_URL', ''))
        echo     print('CERT=' + env.get('NODE_EXTRA_CA_CERTS', ''))
        echo except Exception as e:
        echo     print('ERR=' + str(e))
    ) > "%TMP_PY%"

    for /f "delims=" %%A in ('!PYTHON! "%TMP_PY%" "%CLAUDE_SETTINGS%" 2^>nul') do (
        set "LINE=%%A"
        if "!LINE:~0,5!"=="AUTH=" set "AUTH_TOKEN=!LINE:~5!"
        if "!LINE:~0,4!"=="URL="  set "BEDROCK_URL=!LINE:~4!"
        if "!LINE:~0,5!"=="CERT=" set "SSL_CERT=!LINE:~5!"
        if "!LINE:~0,4!"=="ERR="  echo  WARNING: Could not parse settings.json - !LINE:~4!
    )

    if not "!AUTH_TOKEN!"=="" (
        echo  Credentials found - AI Analysis will be configured.
    ) else (
        echo  WARNING: No ANTHROPIC_AUTH_TOKEN found in settings.json - AI Analysis will be disabled.
    )

) else (
    echo.
    echo  NOTE: Claude Code is not installed on this machine.
    echo  Salesforce provides Claude deployed on AWS Bedrock, which requires
    echo  Claude Code to be installed and configured with your Salesforce
    echo  credentials. Since it is not detected here, everything in the app
    echo  will work normally EXCEPT the AI Analysis of TCP captures.
    echo  To enable AI Analysis, install Claude Code via your Salesforce
    echo  IT portal and re-run this script.
    echo.
)

:: ── 4. Write backend\.env ──────────────────────────────────
echo.
echo [4/7] Writing backend\.env...

set "ENV_FILE=%BACKEND_DIR%\.env"
echo # Auto-generated by install.bat - do not commit > "%ENV_FILE%"
if not "!AUTH_TOKEN!"==""  echo ANTHROPIC_AUTH_TOKEN=!AUTH_TOKEN!  >> "%ENV_FILE%"
if not "!BEDROCK_URL!"=="" echo ANTHROPIC_BEDROCK_BASE_URL=!BEDROCK_URL! >> "%ENV_FILE%"
if not "!SSL_CERT!"==""    echo SSL_CERT_FILE=!SSL_CERT! >> "%ENV_FILE%"
echo  Written: %ENV_FILE%

:: Quick connectivity check - warn but never block
if not "!BEDROCK_URL!"=="" (
    echo  Testing AI gateway connectivity...

    (
        echo import urllib.request, ssl, os, sys
        echo url  = sys.argv[1]
        echo cert = sys.argv[2] if len(sys.argv) > 2 else ''
        echo try:
        echo     ctx = ssl.create_default_context()
        echo     if cert and os.path.exists(cert):
        echo         ctx.load_verify_locations(cert)
        echo     urllib.request.urlopen(url, timeout=5, context=ctx)
        echo     print('REACHABLE')
        echo except:
        echo     print('UNREACHABLE')
    ) > "%TMP_PY%"

    for /f "delims=" %%R in ('!PYTHON! "%TMP_PY%" "!BEDROCK_URL!" "!SSL_CERT!" 2^>nul') do set "GW_STATUS=%%R"

    if "!GW_STATUS!"=="REACHABLE" (
        echo  AI gateway reachable - full AI Analysis enabled.
    ) else (
        echo.
        echo  NOTICE: The Salesforce AI gateway is not reachable from this machine.
        echo  This is normal on machines outside the Salesforce corporate network.
        echo  AI Analysis will show "not available" - all PCAP analysis features
        echo  work normally without it.
        echo.
    )
)

:: ── 5. Python venv + dependencies ──────────────────────────
echo.
echo [5/7] Installing Python dependencies...

set "VENV_DIR=%BACKEND_DIR%\.venv"
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo  Creating virtual environment...
    !PYTHON! -m venv "%VENV_DIR%"
    if errorlevel 1 ( echo  ERROR: venv creation failed. & pause & exit /b 1 )
)

set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

"%VENV_PYTHON%" -m pip install --upgrade pip --quiet
"%VENV_PIP%" install -r "%BACKEND_DIR%\requirements.txt"
if errorlevel 1 ( echo  ERROR: pip install failed. & pause & exit /b 1 )
echo  Python dependencies installed.

:: ── 6. Node / frontend deps ────────────────────────────────
echo.
echo [6/7] Installing Node.js dependencies...

cd /d "%FRONTEND_DIR%"
call npm install
if errorlevel 1 ( echo  ERROR: npm install failed. & pause & exit /b 1 )
echo  Node dependencies installed.

:: Cleanup temp file
if exist "%TMP_PY%" del /q "%TMP_PY%"

:: ── 7. Launch ──────────────────────────────────────────────
echo.
echo [7/7] Starting servers...

:: Pick a free backend port
set "BACKEND_PORT=8001"
netstat -ano 2>nul | findstr ":8001 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    set "BACKEND_PORT=8002"
    echo  Port 8001 in use - switching to 8002.
)

echo.
echo  Backend : http://localhost:!BACKEND_PORT!
echo  Frontend: http://localhost:5173
echo.
echo  Two new windows will open for backend and frontend.
echo  Close them to stop the servers.
echo.

start "TCP Analyzer Backend" cmd /k "cd /d "%BACKEND_DIR%" && "%VENV_PYTHON%" -m uvicorn app.main:app --host 0.0.0.0 --port !BACKEND_PORT! --reload"
timeout /t 4 /nobreak >nul
start "TCP Analyzer Frontend" cmd /k "cd /d "%FRONTEND_DIR%" && npm run dev"
timeout /t 4 /nobreak >nul
start "" "http://localhost:5173"

echo  Done! App should open in your browser.
echo.
pause
endlocal
