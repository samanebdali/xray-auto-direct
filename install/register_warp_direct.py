#!/usr/bin/env python3
"""Register a fresh WARP account through Cloudflare's device API as a wgcf fallback."""
import argparse
import datetime as dt
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

def wg_key(command, data=None):
    return subprocess.check_output(command, input=data, text=True).strip()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    args=p.parse_args()
    private=wg_key(["wg","genkey"])
    public=wg_key(["wg","pubkey"], private+"\n")
    body=json.dumps({
        "fcm_token":"",
        "install_id":"",
        "key":public,
        "locale":"en_US",
        "model":"PC",
        "tos":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),
        "type":"Android",
    }).encode()
    last=None
    for version in ("v0a4005","v0a1922"):
        req=urllib.request.Request(
            "https://api.cloudflareclient.com/"+version+"/reg",
            data=body,
            headers={"Content-Type":"application/json","User-Agent":"okhttp/3.12.1","CF-Client-Version":"a-6.3-"+version[3:]},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                data=json.load(response)
            if not data.get("id") or not data.get("token"):
                raise RuntimeError("Cloudflare registration response is incomplete")
            license_key=(data.get("account") or {}).get("license","")
            text="access_token = "+repr(data["token"])+"\n"+"device_id = "+repr(data["id"])+"\n"+"license_key = "+repr(license_key)+"\n"+"private_key = "+repr(private)+"\n"
            args.output.parent.mkdir(parents=True,exist_ok=True)
            temp=args.output.with_suffix(".tmp")
            temp.write_text(text,encoding="utf-8")
            os.chmod(temp,0o600)
            os.replace(temp,args.output)
            print("direct_warp_registration=ok")
            return
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError) as exc:
            last=exc
    raise SystemExit("direct Cloudflare registration failed: "+str(last))

if __name__=="__main__":
    main()
