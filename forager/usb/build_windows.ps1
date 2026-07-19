# Build a standalone Windows HexBee Forager for a USB triage stick.
# Produces a single forager.exe that needs NO Python on the target machine,
# then assembles the ready-to-copy USB layout in  forager/usb/dist/HexBee-Forager-USB.
#
# Requires: Python + pip on THIS build machine (not the target).
#   pip install pyinstaller
#   powershell -ExecutionPolicy Bypass -File forager\usb\build_windows.ps1

$ErrorActionPreference = "Stop"
$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$forager  = Split-Path -Parent $here            # forager/
$work     = Join-Path $here "_build"
$out      = Join-Path $here "dist\HexBee-Forager-USB"

Write-Host "==> Building forager.exe (PyInstaller, onefile)"
python -m PyInstaller --onefile --console --name forager `
    --paths $forager `
    --hidden-import psutil `
    --collect-submodules hexbee_forager `
    --distpath (Join-Path $work "dist") `
    --workpath (Join-Path $work "work") `
    --specpath $work `
    (Join-Path $here "entry.py")

Write-Host "==> Assembling USB layout at $out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "collections") | Out-Null
Copy-Item (Join-Path $work "dist\forager.exe") $out -Force
Copy-Item (Join-Path $here "RUN-WINDOWS.bat")   $out -Force
Copy-Item (Join-Path $here "run-linux.sh")      $out -Force
Copy-Item (Join-Path $here "forager.example.json") $out -Force
Copy-Item (Join-Path $here "USB-README.txt")    $out -Force

Write-Host ""
Write-Host "Done. Copy the whole folder to a USB stick:"
Write-Host "  $out"
Write-Host "Edit forager.example.json -> forager.json with your Hive URL + ingest key"
Write-Host "(optional: leave it out to capture offline onto the stick)."
