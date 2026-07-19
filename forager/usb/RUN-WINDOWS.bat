@echo off
REM ===================================================================
REM  HexBee Forager - USB triage launcher (Windows)
REM  Authorized forensic collection only. Read-only: does not modify
REM  this machine. Run as Administrator for full process/network data.
REM ===================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

:menu
cls
echo ============================================
echo    HexBee Forager - USB triage
echo    Host: %COMPUTERNAME%
echo ============================================
echo.
echo   [1]  Collect now  (one-shot snapshot)
echo   [2]  Monitor      (watch for new activity)
echo   [3]  Status       (config + backlog)
echo   [4]  Quit
echo.
set /p choice="Choose 1-4: "

if "%choice%"=="1" goto collect
if "%choice%"=="2" goto watch
if "%choice%"=="3" goto status
if "%choice%"=="4" exit /b 0
goto menu

:collect
set STAMP=%COMPUTERNAME%_%DATE:/=-%_%TIME::=-%
set STAMP=%STAMP: =_%
set OUTFILE=collections\%STAMP%.json
echo.
echo Collecting from %COMPUTERNAME% ...
forager.exe collect --output "%OUTFILE%"
echo.
if exist forager.json (
    echo Hive config found - submitting collection...
    forager.exe submit "%OUTFILE%"
) else (
    echo Saved to the USB only:  %OUTFILE%
    echo Submit later:  forager.exe --hive http://HIVE:8080 --key KEY submit "%OUTFILE%"
)
echo.
pause
goto menu

:watch
echo.
echo Monitoring %COMPUTERNAME% - press Ctrl-C to stop and return.
forager.exe watch --interval 60
goto menu

:status
echo.
forager.exe status
echo.
pause
goto menu
