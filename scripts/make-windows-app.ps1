# Install HexBee as a Windows app — Start Menu and Desktop shortcuts that
# launch the forensics console with no console window and no typed commands.
#
#   powershell -ExecutionPolicy Bypass -File scripts\make-windows-app.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\make-windows-app.ps1 -Uninstall
#
# No administrator rights required: everything is written under the current
# user's profile.
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcuts = @((Join-Path $startMenu "HexBee Forensics.lnk"),
               (Join-Path ([Environment]::GetFolderPath("Desktop")) "HexBee Forensics.lnk"))

if ($Uninstall) {
    foreach ($s in $shortcuts) { if (Test-Path $s) { Remove-Item $s; Write-Host "removed $s" } }
    Write-Host "Removed. Evidence in %LOCALAPPDATA%\HexBee was left alone."
    exit 0
}

# pythonw.exe runs the launcher without a console window, which is the whole
# difference between "an app" and "a script that leaves a black box open".
$pythonw = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
if (-not $pythonw) {
    Write-Error @"
Python 3 was not found on PATH.

Install it from https://www.python.org/downloads/ and tick
"Add python.exe to PATH" during setup, then run this again.
"@
    exit 1
}

$launcher = Join-Path $repo "scripts\hexbee_launcher.py"
if (-not (Test-Path $launcher)) { Write-Error "launcher missing: $launcher"; exit 1 }

# Convert the logo to .ico so the shortcut carries the HexBee mark. Falls back
# to the interpreter's own icon rather than failing the install.
$icon = Join-Path $repo "hive\hexbee_hive\static\hexbee.ico"
$png  = Join-Path $repo "hive\hexbee_hive\static\logo-256.png"
if ((-not (Test-Path $icon)) -and (Test-Path $png)) {
    try {
        Add-Type -AssemblyName System.Drawing
        $bmp = [System.Drawing.Bitmap]::FromFile($png)
        $ico = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
        $stream = [System.IO.File]::Create($icon)
        $ico.Save($stream); $stream.Close(); $bmp.Dispose()
        Write-Host "    icon built from logo-256.png"
    } catch { Write-Host "    could not build icon - using the default" }
}

$shell = New-Object -ComObject WScript.Shell
foreach ($path in $shortcuts) {
    $parent = Split-Path -Parent $path
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $link = $shell.CreateShortcut($path)
    $link.TargetPath       = $pythonw
    $link.Arguments        = "`"$launcher`""
    $link.WorkingDirectory = $repo
    $link.Description      = "HexBee Forensics - evidence console"
    if (Test-Path $icon) { $link.IconLocation = $icon }
    $link.Save()
    Write-Host "created $path"
}

Write-Host ""
Write-Host "Installed. Open HexBee from the Start Menu or the Desktop."
Write-Host "  Dashboard   http://127.0.0.1:8080"
Write-Host "  Evidence    $env:LOCALAPPDATA\HexBee"
Write-Host ""
Write-Host "First launch builds a private Python environment and takes a minute."
Write-Host "The browser opens on its own when it is ready."
