#!/usr/bin/env bash
# Runs the IDS engine NATIVELY (outside Docker) so it can capture traffic on
# the real host NIC instead of Docker's internal bridge network. 
# PREREQUISITES
#   1. Java 17+ on PATH        (java -version)
#   2. libpcap installed        (sudo apt install libpcap-dev  — Debian/Ubuntu/Kali base)
#   3. Backend + db already running via docker compose (friend-compose.linux.yml
#      or friend-compose.desktop.yml) — do NOT also run ids_engine in Docker
#      at the same time, or you'll get two engines both trying to log in and
#      submit alerts.
#   4. engine-1.0.0.jar in this folder.
#
# RUN AS ROOT — raw packet capture needs it:
#   sudo ./run-engine-native.sh

set -euo pipefail

# --- config: must match your .env ---
export IDS_ENGINE_USER="Tiron bby"
export IDS_ENGINE_PASS="AIMAN"
export IDS_ENGINE_KEY="piQLNx4vEFAmJ1IaMC1993hv9x8IpyQ7ij9J7orJGp8"

# Find real interfaces with: ip -o link show
# Leave "all" to auto-detect, or set a specific name (e.g. enp0s3, wlan0).
IFACE="all"
BACKEND="http://localhost:8080"

if [ "$EUID" -ne 0 ]; then
  echo "Run this with sudo — raw capture needs root." >&2
  exit 1
fi

echo "Stop the containerized engine first if it's running:"
echo "  docker stop ids_engine"
echo ""
echo "Starting native IDS engine on interface '$IFACE' against $BACKEND ..."
java -jar engine-1.0.0.jar "$IFACE" "$BACKEND"