#!/usr/bin/env python3
"""Atomically bootstrap a simple 3x-ui user WARP route without restarting Xray."""
import argparse, json, os, shutil, sqlite3, subprocess, sys, tempfile
from pathlib import Path

def die(message):
    raise SystemExit(message)

def run(command):
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--xray", required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--outbound", type=Path, required=True)
    p.add_argument("--inbound-tag", required=True)
    p.add_argument("--api", default="127.0.0.1:62789")
    p.add_argument("--backup-dir", type=Path, required=True)
    args=p.parse_args()
    primary=json.load(open(args.outbound,encoding="utf-8"))
    tag=primary.get("tag","")
    if primary.get("protocol")!="wireguard" or not tag:
        die("primary outbound is not a tagged WireGuard config")
    old_raw=args.config.read_text(encoding="utf-8")
    old=json.loads(old_raw)
    con=sqlite3.connect(args.db)
    try:
        rows=con.execute("SELECT id,value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id").fetchall()
        if len(rows)!=1: die("xrayTemplateConfig must be exactly one row")
        row_id, db_old=rows[0]
        template=json.loads(db_old)
    finally: con.close()
    for cfg in (old,template):
        if any(x.get("tag")==tag for x in cfg.get("outbounds",[])):
            die("primary outbound tag already exists")
        rules=cfg.get("routing",{}).get("rules",[])
        if not isinstance(rules,list): die("routing rules missing")
        if cfg.get("routing",{}).get("balancers"): die("bootstrap refuses balancer-based routing")
        for rule in rules:
            if rule.get("inboundTag") and args.inbound_tag in rule["inboundTag"] and not (rule.get("domain") or rule.get("ip")):
                die("bootstrap refuses an existing catch-all for selected inbound")
            if not (rule.get("domain") or rule.get("ip")):
                is_api = rule.get("outboundTag") == "api" and rule.get("inboundTag") == ["api"]
                is_blocked_protocol = rule.get("outboundTag") == "blocked" and rule.get("protocol") == ["bittorrent"]
                if not (is_api or is_blocked_protocol):
                    die("bootstrap requires only specific rules plus standard API/BitTorrent rules")
    rule={"type":"field","inboundTag":[args.inbound_tag],"outboundTag":tag}
    new=json.loads(old_raw); new["outbounds"].append(primary); new.setdefault("routing",{}).setdefault("rules",[]).append(rule)
    new_tpl=json.loads(db_old); new_tpl["outbounds"].append(primary); new_tpl.setdefault("routing",{}).setdefault("rules",[]).append(rule)
    args.backup_dir.mkdir(parents=True,exist_ok=True)
    shutil.copy2(args.config,args.backup_dir/"pre-primary-bootstrap.config.json")
    shutil.copy2(args.db,args.backup_dir/"pre-primary-bootstrap.db")
    with tempfile.TemporaryDirectory() as d:
        staged=Path(d)/"config.json"; route_old=Path(d)/"route-old.json"; route_new=Path(d)/"route-new.json"; outbound_cfg=Path(d)/"outbound.json"
        staged.write_text(json.dumps(new,indent=2)+"\n"); route_old.write_text(json.dumps({"routing":old.get("routing",{})})); route_new.write_text(json.dumps({"routing":new.get("routing",{})}))
        run([args.xray,"run","-test","-c",str(staged)])
        pid_before=subprocess.check_output(["pgrep","-o","-f","bin/xray-linux-amd64 -c bin/config.json"],text=True).strip()
        changed=False; added=False
        try:
            con=sqlite3.connect(args.db)
            with con:
                cur=con.execute("UPDATE settings SET value=? WHERE id=? AND value=?",(json.dumps(new_tpl,separators=(",",":")),row_id,db_old))
                if cur.rowcount!=1: die("xrayTemplateConfig changed concurrently")
            con.close(); changed=True
            os.replace(staged,args.config)
            added=True
            run([args.xray,"api","ado","-s",args.api,str(outbound_cfg)])
            run([args.xray,"api","adrules","-s",args.api,str(route_new)])
        except Exception:
            if added:
                subprocess.run([args.xray,"api","rmo","-s",args.api,tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run([args.xray,"api","adrules","-s",args.api,str(route_old)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            args.config.write_text(old_raw,encoding="utf-8")
            if changed:
                con=sqlite3.connect(args.db)
                with con: con.execute("UPDATE settings SET value=? WHERE id=?",(db_old,row_id))
                con.close()
            raise
        pid_after=subprocess.check_output(["pgrep","-o","-f","bin/xray-linux-amd64 -c bin/config.json"],text=True).strip()
        if pid_before!=pid_after: die("Xray PID changed during primary bootstrap")
        run(["systemctl","is-active","--quiet","x-ui.service"])
    print("primary_warp_bootstrap=ok")

if __name__=="__main__": main()
