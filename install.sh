#!/usr/bin/env bash
# Xray Auto-Direct v1 installer for supported x-ui deployments on Ubuntu 22.04/24.04.
# It never restarts x-ui or production Xray.
set -Eeuo pipefail
umask 077

REPO="samanebdali/xray-auto-direct"
RAW=""
ROOT="/etc/xray-auto-direct"
LIB="/usr/local/lib/xray-auto-direct"
STATE="/var/lib/xray-auto-direct"
PORT=20808
APPLY=1

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }
trap 'echo "Installation stopped at line $LINENO. Existing production Xray was not restarted." >&2' ERR

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"
# Resolve one immutable commit before fetching any project file. This prevents a
# CDN race from mixing installer, controller and systemd files from different
# revisions of main.
REV="$(curl -fsSL --connect-timeout 10 "https://api.github.com/repos/$REPO/commits/main" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')" ||
  die "could not resolve the current project revision from GitHub"
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "GitHub returned an invalid project revision"
RAW="https://raw.githubusercontent.com/$REPO/$REV"
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
try:
    legacy=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='routing_rules'").fetchone()
    if legacy:
        raise SystemExit("unsupported panel database layout: this v1 release targets MHSanaei/3x-ui, not legacy Alireza x-ui")
    rows=con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id").fetchall()
    if len(rows)>1:
        raise SystemExit("xrayTemplateConfig has duplicate rows; refusing an ambiguous migration")
    if not rows:
        # 3x-ui's shipped default template is available in memory but may not
        # have a SQLite row yet. The installer will persist an exact copy of
        # the already-running validated config, after creating a DB backup.
        print("template_bootstrap_required=1")
    else:
        db=json.loads(rows[0][0])
        persisted=any(r.get("outboundTag")=="direct" and isinstance(r.get("domain"),list)
                      for r in db.get("routing",{}).get("rules",[]))
        if not persisted:
            raise SystemExit("supported Direct domain rule is missing from persistent 3x-ui template")
        print("template_bootstrap_required=0")
finally:
    con.close()
PY

note "Installing small prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl python3 >/dev/null

install -d -m 0700 "$ROOT" "$STATE" "$STATE/backups" "$LIB" "$LIB/bin" "$STATE/wgcf"
curl -fsSL "$RAW/src/xray-auto-direct.py" -o "$LIB/xray-auto-direct.py"
curl -fsSL "$RAW/install/wgcf_to_shadow.py" -o "$LIB/wgcf_to_shadow.py"
curl -fsSL "$RAW/systemd/xray-auto-direct.service" -o /etc/systemd/system/xray-auto-direct.service
curl -fsSL "$RAW/systemd/xray-autodirect-shadow.service.in" -o /tmp/xray-autodirect-shadow.service
chmod 0700 "$LIB/xray-auto-direct.py" "$LIB/wgcf_to_shadow.py"

# Fresh 3x-ui installs may run from their compiled-in template without a
# xrayTemplateConfig database row. Persist the exact active config once so
# Auto-Direct changes survive the next panel/Xray restart. This does not
# restart, reload, or otherwise interrupt production Xray.
note "Ensuring 3x-ui has a persistent Xray template"
python3 - "$ACTIVE_CFG" "$DB" "$STATE/backups/pre-template-migration.db" <<'PY'
import json, os, sqlite3, sys
cfg_path, db_path, backup_path = sys.argv[1:]
raw=open(cfg_path, encoding='utf-8').read()
cfg=json.loads(raw)
if not isinstance(cfg.get('outbounds'), list) or not isinstance(cfg.get('routing', {}).get('rules'), list):
    raise SystemExit('active config is not a valid 3x-ui Xray template')
src=sqlite3.connect(db_path)
dst=sqlite3.connect(backup_path)
try:
    src.backup(dst)
finally:
    dst.close()
try:
    with src:
        rows=src.execute("SELECT id,value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id").fetchall()
        if len(rows)>1:
            raise SystemExit('xrayTemplateConfig has duplicate rows; refusing an ambiguous migration')
        if not rows:
            src.execute("INSERT INTO settings(key,value) VALUES(?,?)", ('xrayTemplateConfig', raw))
            print('3xui_template_migrated=yes')
        else:
            # Never overwrite an existing admin-authored template.
            persisted=json.loads(rows[0][1])
            if not isinstance(persisted.get('routing', {}).get('rules'), list):
                raise SystemExit('stored xrayTemplateConfig is invalid')
            print('3xui_template_migrated=no')
finally:
    src.close()
os.chmod(backup_path, 0o600)
PY

# Enable local observation through LoggerService only. The Xray process is not
# restarted or reloaded.
note "Enabling the local Xray access log without restarting Xray"
install -d -m 0755 "$(dirname "$ACCESS_LOG")"
stage_dir="$(mktemp -d)"
stage_cfg="$stage_dir/config.json"
stage_tpl="$stage_dir/template.json"
cleanup_log_stage() { rm -rf "$stage_dir"; }
trap cleanup_log_stage EXIT
python3 - "$ACTIVE_CFG" "$DB" "$ACCESS_LOG" "$stage_cfg" "$stage_tpl" <<'PY'
import json, os, sqlite3, sys
active_path, db_path, access_path, cfg_out, tpl_out = sys.argv[1:]
active=json.load(open(active_path,encoding='utf-8'))
con=sqlite3.connect(db_path)
try:
    rows=con.execute("SELECT id,value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id").fetchall()
    if len(rows)!=1: raise SystemExit('xrayTemplateConfig is not exactly one row after migration')
    row_id, old=rows[0]
    template=json.loads(old)
finally:
    con.close()
if not isinstance(template,dict): raise SystemExit('stored xrayTemplateConfig is invalid')
active.setdefault('log',{})['access']=access_path
template.setdefault('log',{})['access']=access_path
open(cfg_out,'w',encoding='utf-8').write(json.dumps(active,indent=2,ensure_ascii=False)+'\n')
open(tpl_out,'w',encoding='utf-8').write(json.dumps({'id':row_id,'old':old,'new':json.dumps(template,ensure_ascii=False)}))
os.chmod(cfg_out,0o600)
PY
"$XRAY_BIN" run -test -c "$stage_cfg" >/dev/null || die "access-log config did not validate"
pid_before="$(pgrep -o -f 'bin/xray-linux-amd64 -c bin/config.json' || true)"
[[ -n "$pid_before" ]] || die "running production Xray PID was not found"
python3 - "$DB" "$stage_tpl" "$stage_cfg" "$ACTIVE_CFG" <<'PY'
import json, os, sqlite3, sys
db_path, tpl_path, staged, active_path=sys.argv[1:]
meta=json.load(open(tpl_path,encoding='utf-8'))
con=sqlite3.connect(db_path)
try:
    with con:
        cur=con.execute("UPDATE settings SET value=? WHERE id=? AND value=?",(meta['new'],meta['id'],meta['old']))
        if cur.rowcount!=1: raise SystemExit('xrayTemplateConfig changed concurrently; access-log update cancelled')
    os.replace(staged,active_path)
finally:
    con.close()
PY
"$XRAY_BIN" api restartlogger -s 127.0.0.1:62789 -t 3 >/dev/null || die "LoggerService refresh failed"
sleep 1
pid_after="$(pgrep -o -f 'bin/xray-linux-amd64 -c bin/config.json' || true)"
[[ "$pid_before" == "$pid_after" ]] || die "Xray PID changed during LoggerService refresh"
systemctl is-active --quiet x-ui.service || die "x-ui became inactive during LoggerService refresh"
[[ -f "$ACCESS_LOG" ]] || die "access log was not created after LoggerService refresh"
trap - EXIT
cleanup_log_stage

# Obtain a pinned-at-install-time wgcf release selected by GitHub's release API.
note "Obtaining wgcf for a fresh, independent WARP identity"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64) wgarch=amd64 ;; arm64) wgarch=arm64 ;; *) die "unsupported architecture: $arch" ;; esac
asset_url="$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest | python3 -c '
import json, sys
arch=sys.argv[1]
for a in json.load(sys.stdin).get("assets",[]):
    u=a.get("browser_download_url","")
    n=a.get("name","")
    if "linux_"+arch in n and not n.endswith((".sha256",".sig")):
        print(u)
        break
' "$wgarch")"
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
      if timeout 30 "$LIB/bin/wgcf" register --accept-tos && timeout 20 "$LIB/bin/wgcf" generate; then
        break
      fi
      [[ "$attempt" == 5 ]] && exit 1
      sleep "$((attempt * 5))"
    done
    [[ -s wgcf-profile.conf ]]
  ) || die "could not register an independent WARP identity after 5 bounded attempts"
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
note "Installing validated Iran IPv4 CIDR data"
curl -fsSL --retry 3 https://www.ipdeny.com/ipblocks/data/countries/ir.zone -o "$ROOT/ir.cidr"
python3 - "$ROOT/ir.cidr" <<'PY'
import ipaddress, sys
lines=[x.strip() for x in open(sys.argv[1]) if x.strip() and not x.lstrip().startswith('#')]
if not lines:
    raise SystemExit('Iran CIDR download was empty')
for line in lines:
    ipaddress.IPv4Network(line, strict=False)
PY
chmod 0640 "$ROOT/ir.cidr"
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
