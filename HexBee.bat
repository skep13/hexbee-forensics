@echo off
REM ===================================================================
REM  HexBee — double-click to start the forensics console on Windows.
REM
REM  First run builds a private Python environment and can take a
REM  minute. After that it starts in a couple of seconds. The console
REM  window closes itself once the dashboard is up.
REM
REM  Nothing here needs administrator rights.
REM ===================================================================
setlocal
cd /d "%~dp0"

REM pythonw runs without a console window; fall back to python so that a
REM missing pythonw shows the error rather than failing silently.
where pythonw >nul 2>&1 && (
    start "" pythonw "%~dp0scripts\hexbee_launcher.py"
    exit /b 0
)
where python >nul 2>&1 || (
    echo Python 3 is required and was not found.
    echo Install it from https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^)
    pause
    exit /b 1
)
python "%~dp0scripts\hexbee_launcher.py"
