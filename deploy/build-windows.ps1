<#
.SYNOPSIS
    Builds the HVPN Windows release binaries and stages them in dist\hvpn-windows.

.DESCRIPTION
    Compiles the workspace in --release mode, then copies the runnable
    Windows binaries (hvpn-client, hvpn-server, hvpn-ctl, hvpn-tray) and the
    example client config into a staging directory for distribution.

    The WinTun kernel driver (wintun.dll) is NOT bundled because it is a
    signed binary that must be downloaded directly from the official source.
    Download wintun.dll from https://wintun.net/ and drop it next to the
    HVPN binaries (hvpn-client.exe and hvpn-server.exe) before running them.

.NOTES
    Run from the repository root:  powershell -File deploy\build-windows.ps1
#>

# Resolve paths relative to this script so it works from anywhere.
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "==> Building HVPN release binaries (this may take a while) ..."
cargo build --workspace --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

$Release = Join-Path $RepoRoot "target\release"
$Dist    = Join-Path $RepoRoot "dist\hvpn-windows"

Write-Host "==> Staging output into $Dist ..."
# Clean and recreate the staging directory.
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

# Binaries to ship.
$Binaries = @("hvpn-client.exe", "hvpn-server.exe", "hvpn-ctl.exe", "hvpn-tray.exe")
foreach ($bin in $Binaries) {
    $src = Join-Path $Release $bin
    if (Test-Path $src) {
        Copy-Item $src -Destination $Dist -Force
        Write-Host "    copied $bin"
    } else {
        Write-Warning "    expected binary not found: $bin"
    }
}

# Ship the example client config so users have a starting point.
$ExampleConfig = Join-Path $RepoRoot "deploy\example-client.toml"
if (Test-Path $ExampleConfig) {
    Copy-Item $ExampleConfig -Destination $Dist -Force
    Write-Host "    copied example-client.toml"
}

Write-Host ""
Write-Host "==> Build complete."
Write-Host "    Output: $Dist"
Write-Host ""
Write-Host "    IMPORTANT: WinTun driver (wintun.dll) is required at runtime."
Write-Host "    Download it from https://wintun.net/ and place wintun.dll next to"
Write-Host "    hvpn-client.exe (and hvpn-server.exe) in the output directory."
Write-Host ""
Write-Host "    Install the client service (auto-starts on boot):"
Write-Host "        .\hvpn-client.exe --install"
Write-Host "    Launch the GUI tray app:"
Write-Host "        .\hvpn-tray.exe"
