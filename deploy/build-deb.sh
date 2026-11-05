#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:-0.1.0}"
ARCH="amd64"
PKG="hvpn_${VERSION}_${ARCH}"

cargo build --release

mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/local/bin"
mkdir -p "$PKG/etc/hvpn"
mkdir -p "$PKG/etc/systemd/system"
mkdir -p "$PKG/var/log/hvpn"

cp target/release/hvpn-server "$PKG/usr/local/bin/"
cp target/release/hvpn-client "$PKG/usr/local/bin/"
cp target/release/hvpn-ctl    "$PKG/usr/local/bin/"
cp deploy/example-server.toml "$PKG/etc/hvpn/server.toml.example"
cp deploy/example-client.toml "$PKG/etc/hvpn/client.toml.example"
cp deploy/hvpn-server.service  "$PKG/etc/systemd/system/"
cp deploy/hvpn-client.service  "$PKG/etc/systemd/system/"

cat > "$PKG/DEBIAN/control" <<EOF
Package: hvpn
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: HVPN Project <hvpn@example.com>
Description: DPI-evasion VPN with post-quantum cryptography
 HVPN is a high-evasion VPN protocol that bypasses deep packet inspection
 and network filtering using adaptive transport camouflage, onion routing,
 and post-quantum hybrid key exchange.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
systemctl daemon-reload || true
EOF
chmod 755 "$PKG/DEBIAN/postinst"

dpkg-deb --build "$PKG"
echo "Built: ${PKG}.deb"
