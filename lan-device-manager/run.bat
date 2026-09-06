@echo off
REM LAN Device Manager - launcher
REM Installs dependencies on first run, then starts the app and opens the UI.

setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

python -c "import fastapi, uvicorn, httpx" >nul 2>nul
if errorlevel 1 (
    echo Installing dependencies, this only happens once...
    python -m pip install --quiet --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo Dependency installation failed.
        pause
        exit /b 1
    )
)

python -m lan_device_manager %*
if errorlevel 1 pause
endlocal
