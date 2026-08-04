# Friend test bundle — Windows native engine launcher.
#
# Run this AFTER friend-compose.desktop.yml is up and you've confirmed you
# can log in to the desktop client as "Tiron bby" / AIMAN. Requires:
#   - Java 17+ on PATH
#   - Npcap installed (https://npcap.com/#download) — check "WinPcap API
#     compatible mode" during install, or packet capture will fail
#   - engine/target/engine-1.0.0.jar already built (mvn -pl engine package,
#     or the full `mvn package` from the IDS/ root)
#
# Usage (from inside share/, in PowerShell):
#   .\run-engine-native.ps1

$ErrorActionPreference = "Stop"

$env:IDS_ENGINE_USER = "Tiron bby"
$env:IDS_ENGINE_PASS = "AIMAN"
$env:IDS_ENGINE_KEY  = "piQLNx4vEFAmJ1IaMC1993hv9x8IpyQ7ij9J7orJGp8"

$jar = Join-Path $PSScriptRoot "..\engine\target\engine-1.0.0.jar"

if (-not (Test-Path $jar)) {
    Write-Error "Can't find $jar — build it first: mvn -pl engine package (run from the IDS/ project root)."
    exit 1
}

Write-Host "Starting engine as '$($env:IDS_ENGINE_USER)' against http://localhost:8080 ..."
Write-Host "(If this window needs to stay open as Administrator for packet capture, re-launch PowerShell as Administrator first.)"

java -jar $jar all http://localhost:8080
