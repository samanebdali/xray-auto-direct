# Xray Auto-Direct v1

A safety-first routing controller for **MHSanaei/3x-ui** on Ubuntu 22.04/24.04.

It keeps diagnostic traffic completely separate from user traffic:

```text
User traffic  → production Xray → primary WARP → Direct fallback
Auto-Direct  → Shadow Xray     → independent Shadow WARP
```

If Shadow WARP is unhealthy, Auto-Direct fails closed: it performs no probe and no promotion.

## Supported topology

- MHSanaei/3x-ui with Xray RoutingService at `127.0.0.1:62789`
- A Direct domain rule using the `direct` outbound
- One selected production user inbound
- Either:
  - an existing user WARP WireGuard outbound; or
  - a simple routing topology eligible for `--bootstrap-primary-warp`

The installer persists the active Xray configuration into 3x-ui's `xrayTemplateConfig` when necessary, so changes survive an x-ui restart. Alireza x-ui is deliberately unsupported.

## Install

Existing primary WARP:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply
```

No primary WARP yet, on a simple route set:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply --bootstrap-primary-warp --inbound-tag YOUR_INBOUND_TAG
```

Bootstrap creates a **new primary WARP identity** with tag `autodirect-primary-warp`; it never reuses the independent Shadow identity. It refuses balancer-based, catch-all, or otherwise ambiguous routing rather than altering an unknown topology.

See the complete [English guide](docs/INSTALL.md) and [راهنمای فارسی](docs/README.fa.md).

## Policy

Edit `/etc/xray-auto-direct/policy.json` to control:

- `pinned_direct_suffixes`: always Direct (payment defaults are included).
- `manual_direct_suffixes`: explicit user-approved Direct destinations.
- `pinned_warp_suffixes`: always WARP and never probed/promoted.

No policy update restarts production Xray. Every live promotion validates a temporary config, backs up config/database, applies through RoutingService, verifies the Xray PID, and rolls back on failure.

## Security

This repository contains no personal UUIDs, private keys, API tokens, panel paths, domains, or IP addresses. Shadow credentials are root-only, its SOCKS listener is loopback-only, and it must never be opened in a firewall.

## License

GPL-3.0.
