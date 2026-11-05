#!/usr/bin/env bash
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/hvpn"
LOG_DIR="/var/log/hvpn"

echo "[hvpn] Installing binaries to $INSTALL_PREFIX"
install -m 755 target/release/hvpn-server "$INSTALL_PREFIX/hvpn-server"
install -m 755 target/release/hvpn-client "$INSTALL_PREFIX/hvpn-client"
install -m 755 target/release/hvpn-ctl    "$INSTALL_PREFIX/hvpn-ctl"

echo "[hvpn] Creating config directory $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "[hvpn] Creating log directory $LOG_DIR"
mkdir -p "$LOG_DIR"

echo "[hvpn] Installing systemd service files"
install -m 644 deploy/hvpn-server.service /etc/systemd/system/
install -m 644 deploy/hvpn-client.service /etc/systemd/system/
systemctl daemon-reload

echo "[hvpn] Installation complete."
echo "       Edit $CONFIG_DIR/server.toml and $CONFIG_DIR/client.toml, then:"
echo "       systemctl enable --now hvpn-server"
