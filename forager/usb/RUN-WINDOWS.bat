@echo off
REM ===================================================================
REM  HexBee Forager - USB triage launcher (Windows)
REM  Authorized forensic collection only. Read-only: does not modify
REM  this machine. Run as Administrator for full process/network data.
REM ===================================================================
setlocal
cd /d "%~dp0"

echo HexBee Forager - collecting from %COMPUTERNAME% ...
echo.

REM Capture to the USB stick first (works with NO network), then also try to
REM ship to the Hive if forager.json / env provides one. Spool stays on the USB.
set STAMP=%COMPUTERNAME%_%DATE:/=-%_%TIME::=-%
set STAMP=%STAMP: =_%
set OUTFILE=collections\%STAMP%.json

forager.exe collect --output "%OUTFILE%"

echo.
if exist forager.json (
    echo Hive config found - submitting collection...
    forager.exe submit "%OUTFILE%"
) else (
    echo No forager.json - collection saved to the USB only:
    echo   %OUTFILE%
    echo Submit it later from a networked machine with:
    echo   forager.exe --hive http://HIVE:8080 --key KEY submit "%OUTFILE%"
)

echo.
echo Done. Safely eject the USB stick.
pause
