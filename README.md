# Xray Auto-Direct v1

A safety-first routing controller for Xray deployments that use Cloudflare WARP as the primary outbound and a stable Direct egress as fallback.

> Status: public package preparation. Do not deploy from this repository until the installer and clean-server validation are released.

## What it will do

- Reads Xray access logs without touching user traffic.
- Sends every diagnostic probe through an isolated **Shadow Xray + Shadow WARP** path.
- Promotes a destination to Direct only when Shadow WARP fails and the Reserved-IP Direct path succeeds.
- Applies ordinary routing changes live through Xray RoutingService.
- Fails closed: if Shadow WARP is unhealthy, it makes no routing change.
- Keeps user-defined pinned domains out of probing.

## Policy

The normal user edit is a policy file:

- `pinned_direct_suffixes`: domains that must use stable Direct egress, including payment domains.
- `pinned_warp_suffixes`: domains that must remain on WARP and must never be probed/promoted.
- `manual_direct_suffixes`: optional explicitly approved Direct destinations.

See [policy.example.json](policy.example.json).

## Security model

```
User → Xray production → WARP or Reserved-IP Direct
                     ↑
Auto-Direct → Shadow Xray → independent Shadow WARP
```

Shadow credentials, listeners, and probes are separate from production. This repository never contains personal UUIDs, private keys, domains, IP addresses, API tokens, or panel paths.

## Planned layout

```
install/   clean-server installer and systemd units
src/       controller and isolated probe code
config/    policy and configuration templates
tests/     parser, rollback, health, and integration tests
docs/      English and Persian operation guides
```

The production design has already been exercised with live routing updates, rollback checks, Shadow-WARP outage isolation, and stress requests. The public v1 release must also pass clean Ubuntu installation and recovery tests.

## License

Added with the first release.
