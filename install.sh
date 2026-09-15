#!/usr/bin/env bash
# Xray Auto-Direct v1 installer for supported x-ui deployments on Ubuntu 22.04/24.04.
# It never restarts x-ui or production Xray.
set -Eeuo pipefail
umask 077

REPO="samanebdali/xray-auto-direct"
RAW="https://raw.githubusercontent.com/$REPO/main"
ROOT="/etc/xray-auto-direct"
LIB="/usr/local/lib/xray-auto-direct"
STATE="/var/lib/xray-auto-direct"
PORT=20808
APPLY=1

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }
trap 'echo "Installation stopped at line $LINENO. Existing production Xray was not restarted." >&2' ERR

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"
case "${1:-}" in
  --dry-run) APPLY=0 ;;
  ""|--apply) ;;
  *) die "Usage: sudo bash install.sh [--apply|--dry-run]" ;;
esac

XRAY_BIN="${XRAY_BIN:-/usr/local/x-ui/bin/xray-linux-amd64}"
XRAY_WORKDIR="${XRAY_WORKDIR:-/usr/local/x-ui}"
ACTIVE_CFG="${ACTIVE_CFG:-/usr/local/x-ui/bin/config.json}"
DB="${XRAY_DB:-/etc/x-ui/x-ui.db}"
ACCESS_LOG="${XRAY_ACCESS_LOG:-/var/log/x-ui/access.log}"
[[ -x "$XRAY_BIN" ]] || die "Xray binary not found: $XRAY_BIN"
[[ -f "$ACTIVE_CFG" ]] || die "Xray config not found: $ACTIVE_CFG"
[[ -f "$DB" ]] || die "x-ui database not found: $DB"
[[ -f "$ACCESS_LOG" ]] || die "x-ui access log not found: $ACCESS_LOG"

note "Checking live routing prerequisites (read-only)"
"$XRAY_BIN" api lsrules -s 127.0.0.1:62789 -t 3 >/dev/null ||
  die "Xray RoutingService is unavailable on 127.0.0.1:62789; enable it before installing."
python3 - "$ACTIVE_CFG" "$DB" <<'PY'
import json, sqlite3, sys
cfg=json.load(open(sys.argv[1]))
if not any(r.get("outboundTag")=="direct" and isinstance(r.get("domain"),list)
           for r in cfg.get("routing",{}).get("rules",[])):
    raise SystemExit("supported Direct domain rule is missing from active Xray config")
con=sqlite3.connect(sys.argv[2])
row=con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
con.close()
if not row:
    raise SystemExit("xrayTemplateConfig is missing from x-ui database")
db=json.loads(row[0])
if not any(r.get("outboundTag")=="direct" and isinstance(r.get("domain"),list)
           for r in db.get("routing",{}).get("rules",[])):
    raise SystemExit("supported Direct domain rule is missing from x-ui database template")
PY

note "Installing small prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl python3 xtables-addons-common >/dev/null

install -d -m 0700 "$ROOT" "$STATE" "$STATE/backups" "$LIB" "$LIB/bin" "$STATE/wgcf"
curl -fsSL "$RAW/src/xray-auto-direct.py" -o "$LIB/xray-auto-direct.py"
curl -fsSL "$RAW/install/wgcf_to_shadow.py" -o "$LIB/wgcf_to_shadow.py"
curl -fsSL "$RAW/systemd/xray-auto-direct.service" -o /etc/systemd/system/xray-auto-direct.service
curl -fsSL "$RAW/systemd/xray-autodirect-shadow.service.in" -o /tmp/xray-autodirect-shadow.service
chmod 0700 "$LIB/xray-auto-direct.py" "$LIB/wgcf_to_shadow.py"

# Obtain a pinned-at-install-time wgcf release selected by GitHub's release API.
note "Obtaining wgcf for a fresh, independent WARP identity"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64) wgarch=amd64 ;; arm64) wgarch=arm64 ;; *) die "unsupported architecture: $arch" ;; esac
asset_url="$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest | python3 - "$wgarch" <<'PY'
import json, sys
arch=sys.argv[1]
for a in json.load(sys.stdin).get("assets",[]):
    u=a.get("browser_download_url","")
    n=a.get("name","")
    if "linux_"+arch in n and not n.endswith((".sha256",".sig")):
        print(u); break
PY
)"
[[ -n "$asset_url" ]] || die "could not locate a wgcf release for linux_$wgarch"
curl -fL --retry 3 --connect-timeout 10 "$asset_url" -o "$LIB/bin/wgcf"
chmod 0700 "$LIB/bin/wgcf"
"$LIB/bin/wgcf" --help >/dev/null 2>&1 || die "downloaded wgcf binary is not executable"

# A retry is intentionally bounded: a registration-rate limit must fail safely, not reuse production WARP.
if [[ ! -f "$STATE/wgcf/wgcf-profile.conf" ]]; then
  (
    cd "$STATE/wgcf"
    for attempt in 1 2 3 4 5; do
      rm -f wgcf-account.toml wgcf-profile.conf
      if "$LIB/bin/wgcf" register --accept-tos && "$LIB/bin/wgcf" generate; then
        break
      fi
      [[ "$attempt" == 5 ]] && exit 1
      sleep "$((attempt * 5))"
    done
    [[ -s wgcf-profile.conf ]]
  ) || die "could not register an independent WARP identity after 5 attempts"
fi

note "Generating isolated Shadow Xray configuration"
python3 "$LIB/wgcf_to_shadow.py" --wgcf "$STATE/wgcf/wgcf-profile.conf" --output "$ROOT/shadow.json" --port "$PORT"
"$XRAY_BIN" run -test -c "$ROOT/shadow.json" >/dev/null ||
  die "generated Shadow Xray configuration did not validate"

sed -e "s|@XRAY_BIN@|$XRAY_BIN|g" -e "s|@XRAY_WORKDIR@|$XRAY_WORKDIR|g" \
  /tmp/xray-autodirect-shadow.service > /etc/systemd/system/xray-autodirect-shadow.service
rm -f /tmp/xray-autodirect-shadow.service
cat > "$ROOT/controller.env" <<EOF
XRAY_AUTODIRECT_APPLY=$APPLY
EOF
chmod 0600 "$ROOT/controller.env"
if [[ ! -f "$ROOT/policy.json" ]]; then
  curl -fsSL "$RAW/policy.example.json" -o "$ROOT/policy.json"
  chmod 0640 "$ROOT/policy.json"
fi

systemctl daemon-reload
systemctl enable --now xray-autodirect-shadow.service
sleep 2
systemctl is-active --quiet xray-autodirect-shadow.service || die "Shadow service did not start"
ss -ltnH "sport = :$PORT" | grep -q "127.0.0.1:$PORT" ||
  die "Shadow SOCKS listener is not bound to 127.0.0.1:$PORT"
trace="$(curl -4 -fsS --socks5-hostname "127.0.0.1:$PORT" --connect-timeout 3 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace)" ||
  die "Shadow WARP trace failed"
grep -Eq '^warp=(on|plus)$' <<<"$trace" || die "Shadow is not using WARP; refusing to enable controller"

systemctl enable --now xray-auto-direct.service
systemctl is-active --quiet xray-auto-direct.service || die "controller did not start"
"$LIB/xray-auto-direct.py" --selftest || die "post-install self-test failed"

note "Installed successfully."
note "Production Xray/x-ui was not restarted or reloaded."
if [[ "$APPLY" == 1 ]]; then
  note "Auto-promotion is ENABLED. Edit $ROOT/policy.json to pin Direct or WARP suffixes."
else
  note "Dry-run mode is ENABLED. Set XRAY_AUTODIRECT_APPLY=1 in $ROOT/controller.env and restart only xray-auto-direct.service when ready."
fi
