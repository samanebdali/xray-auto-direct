#!/usr/bin/env python3
"""Convert a wgcf profile to either an isolated Shadow config or one Xray WireGuard outbound."""
import argparse
import base64
import configparser
import json
import os
from pathlib import Path

def get(section, key):
    value = section.get(key, fallback="").strip()
    if not value:
        raise ValueError(f"missing {key} in wgcf profile")
    return value

def reserved_bytes(raw):
    raw = raw.strip()
    if not raw:
        return None
    if "," in raw:
        values = [int(x.strip()) for x in raw.split(",")]
        if len(values) != 3 or any(x < 0 or x > 255 for x in values):
            raise ValueError("invalid Reserved value in wgcf profile")
        return base64.b64encode(bytes(values)).decode()
    base64.b64decode(raw, validate=True)
    return raw

def wireguard_outbound(wgcf, tag):
    if not tag or len(tag) > 128 or not all(c.isalnum() or c in "._-" for c in tag):
        raise ValueError("invalid outbound tag")
    cp = configparser.ConfigParser(interpolation=None)
    if not cp.read(wgcf):
        raise ValueError("cannot read wgcf profile")
    interface, peer = cp["Interface"], cp["Peer"]
    addresses = [x.strip() for x in get(interface, "Address").split(",") if x.strip()]
    if not addresses:
        raise ValueError("no interface address")
    peer_cfg = {"publicKey": get(peer, "PublicKey"), "endpoint": get(peer, "Endpoint")}
    reserved = reserved_bytes(peer.get("Reserved", fallback=""))
    if reserved:
        peer_cfg["reserved"] = reserved
    return {"tag": tag, "protocol": "wireguard", "settings": {
        "secretKey": get(interface, "PrivateKey"), "address": addresses, "peers": [peer_cfg],
        "mtu": int(interface.get("MTU", fallback="1280")), "noKernelTun": True,
        "domainStrategy": "ForceIPv4"}}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--wgcf", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--port", type=int, default=20808)
    p.add_argument("--outbound-only", action="store_true")
    p.add_argument("--tag", default="autodirect-primary-warp")
    args = p.parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("invalid local SOCKS port")
    try:
        outbound = wireguard_outbound(args.wgcf, args.tag)
        if args.outbound_only:
            result = outbound
        else:
            socks_tag = "autodirect-shadow-socks"
            outbound["tag"] = "autodirect-shadow-warp"
            result = {"log":{"loglevel":"warning"}, "inbounds":[{"tag":socks_tag,"listen":"127.0.0.1","port":args.port,"protocol":"socks","settings":{"auth":"noauth","udp":True}}], "outbounds":[outbound], "routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":[socks_tag],"outboundTag":"autodirect-shadow-warp"}]}}
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"invalid wgcf profile: {exc}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix(".tmp")
    temp.write_text(json.dumps(result, indent=2) + "\n")
    os.chmod(temp, 0o600)
    os.replace(temp, args.output)

if __name__ == "__main__":
    main()
