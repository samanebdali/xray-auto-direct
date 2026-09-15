#!/usr/bin/env python3
"""Register a fresh WARP account through Cloudflare's device API as a wgcf fallback."""
import argparse
import base64
import datetime as dt
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

def x25519_public(private):
    # RFC 7748 Montgomery ladder; avoids a wireguard-tools dependency.
    p=(1<<255)-19
    k=bytearray(private)
    k[0]&=248; k[31]&=127; k[31]|=64
    x1=9; x2=1; z2=0; x3=9; z3=1; swap=0
    for bit in range(254,-1,-1):
        kt=(k[bit//8] >> (bit&7)) & 1
        swap ^= kt
        if swap: x2,x3=x3,x2; z2,z3=z3,z2
        swap=kt
        a=(x2+z2)%p; aa=(a*a)%p; b=(x2-z2)%p; bb=(b*b)%p; e=(aa-bb)%p
        c=(x3+z3)%p; d=(x3-z3)%p; da=(d*a)%p; cb=(c*b)%p
        x3=((da+cb)*(da+cb))%p; z3=(x1*(da-cb)*(da-cb))%p
        x2=(aa*bb)%p; z2=(e*(aa+121665*e))%p
    if swap: x2,x3=x3,x2; z2,z3=z3,z2
    return (x2*pow(z2,p-2,p))%p

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    args=p.parse_args()
    private_raw=os.urandom(32)
    private=base64.b64encode(private_raw).decode()
    public=base64.b64encode(x25519_public(private_raw).to_bytes(32,"little")).decode()
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
