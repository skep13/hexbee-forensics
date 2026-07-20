# ===================================================================
#  HexBee — one-command local test on Windows.
#  Right-click > Run with PowerShell, or:
#     powershell -ExecutionPolicy Bypass -File try-hexbee.ps1
#  It installs HexBee into a venv, starts the Hive, loads a demo
#  incident, and opens the dashboard. Login: admin / hexbee-demo-1
# ===================================================================
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$venv = Join-Path $root ".venv"
$py   = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    py -m venv $venv
}

Write-Host "Installing HexBee (hive, comb, queen, forager)..." -ForegroundColor Yellow
& $py -m pip install -q --upgrade pip
& $py -m pip install -q -e "$root\hive" -e "$root\comb" -e "$root\queen" -e "$root\forager"

# Local test config: data + a demo ingest key, kept inside the repo folder.
$env:HEXBEE_DATA_DIR   = Join-Path $root "dev-data"
$env:HEXBEE_INGEST_KEY = "devkey"

Write-Host "Initialising database + demo admin..." -ForegroundColor Yellow
& $py -m hexbee_hive.cli init
& $py "$root\scripts\demo_seed.py"

Write-Host "Starting the Hive..." -ForegroundColor Yellow
$web = Start-Process -FilePath $py -ArgumentList "-m","hexbee_hive.cli","web" -PassThru
Start-Sleep -Seconds 4

Write-Host "Loading a demo incident (simulated Scout)..." -ForegroundColor Yellow
& $py "$root\scout\simulator\scout_sim.py" --rest http://127.0.0.1:8080 --key devkey --scenario incident

Start-Process "http://127.0.0.1:8080"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " HexBee is running:  http://127.0.0.1:8080" -ForegroundColor Green
Write-Host " Login:  admin  /  hexbee-demo-1" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host " Try more:"
Write-Host "   .venv\Scripts\hexbee-forager --hive http://127.0.0.1:8080 --key devkey collect"
Write-Host "   .venv\Scripts\hexbee-comb serve"
Write-Host ""
Write-Host " Stop the Hive later with:  Stop-Process -Id $($web.Id)"
