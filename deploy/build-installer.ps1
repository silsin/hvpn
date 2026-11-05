# HVPN Windows Installer Build Script
# Requires: NSIS 3.x (https://nsis.sourceforge.io/)
# Run from the repo root: .\deploy\build-installer.ps1

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent

Write-Host "=== HVPN Installer Build ==="

# 1. Check NSIS is installed
try {
    $null = & makensis /? 2>&1
    Write-Host "[OK] NSIS found"
} catch {
    Write-Host "[ERROR] NSIS not found. Download and install it from: https://nsis.sourceforge.io/Download"
    Write-Host "        Then add 'C:\Program Files (x86)\NSIS' to your PATH and re-run this script."
    exit 1
}

# 2. Build release binaries
Write-Host "Building release binaries..."
Push-Location $RepoRoot
cargo build --release
Pop-Location
Write-Host "[OK] Build complete"

# 3. Copy to staging directory
$Staging = Join-Path $RepoRoot 'deploy\staging'
New-Item -ItemType Directory -Force -Path $Staging | Out-Null

$ReleaseDir = Join-Path $RepoRoot 'target\release'

Copy-Item (Join-Path $ReleaseDir 'hvpn-client.exe') $Staging -Force
Copy-Item (Join-Path $ReleaseDir 'hvpn-tray.exe')   $Staging -Force
Copy-Item (Join-Path $ReleaseDir 'hvpn-ctl.exe')    $Staging -Force

# Copy example config if it exists
$ExampleConfig = Join-Path $RepoRoot 'example-client.toml'
if (Test-Path $ExampleConfig) {
    Copy-Item $ExampleConfig (Join-Path $Staging 'example-client.toml') -Force
}

Write-Host "[OK] Binaries staged to $Staging"

# 4. Create dist directory
$Dist = Join-Path $RepoRoot 'dist'
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

# 5. Run NSIS
Write-Host "Running NSIS compiler..."
Push-Location $RepoRoot
makensis deploy\installer.nsi
Pop-Location

Write-Host "[OK] Installer created at $Dist\hvpn-setup.exe"
Write-Host "=== Done ==="
