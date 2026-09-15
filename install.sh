#!/usr/bin/env bash
set -Eeuo pipefail

REPO_RAW="https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main"
INSTALL_DIR="/etc/xray-auto-direct"
BIN="/usr/local/sbin/xray-auto-direct"
UNIT="/etc/systemd/system/xray-auto-direct.service"
XUI_DIR="${XUI_DIR:-/usr/local/x-ui}"
XRAY="${XUI_DIR}/bin/xray-linux-amd64"
CONFIG="${XUI_DIR}/bin/config.json"
DB="/etc/x-ui/x-ui.db"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root."; exit 1; }
for file in "$XRAY" "$CONFIG" "$DB"; do [[ -e "$file" ]] || { echo "Unsupported host: missing $file"; exit 1; }; done
command -v curl >/dev/null || { apt-get update -y; apt-get install -y curl; }
systemctl is-active --quiet xray-autodirect-shadow.service || {
  echo "Shadow WARP is not installed. Refusing to start: production probes must stay isolated."
  echo "Use the forthcoming full installer or install the Shadow service first."
  exit 2
}

install -d -m 0750 "$INSTALL_DIR"
curl -fsSL "$REPO_RAW/src/xray-auto-direct.py" -o "$BIN"
curl -fsSL "$REPO_RAW/policy.example.json" -o "$INSTALL_DIR/policy.json"
chmod 0755 "$BIN"
chmod 0640 "$INSTALL_DIR/policy.json"
python3 -m py_compile "$BIN"

cat > "$UNIT" <<EOF
[Unit]
Description=Xray Auto-Direct v1
After=network-online.target x-ui.service xray-autodirect-shadow.service
Wants=network-online.target
Requires=xray-autodirect-shadow.service

[Service]
Type=simple
Environment=XRAY_AUTODIRECT_APPLY=1
ExecStart=$BIN
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now xray-auto-direct.service
systemctl is-active --quiet xray-auto-direct.service
echo "Installed. Edit $INSTALL_DIR/policy.json, then restart xray-auto-direct."
