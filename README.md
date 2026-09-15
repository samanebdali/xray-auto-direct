# Xray Auto-Direct v1

A safety-first routing controller for **MHSanaei/3x-ui** deployments that use Cloudflare WARP as the primary outbound and a stable Direct egress as fallback.

> Status: installer implementation is present, but the first release is not yet certified. Do **not** deploy it to production until clean-server and recovery validation are complete.

## What it does

- Reads Xray access logs without touching user traffic.
- Sends every diagnostic probe through an isolated **Shadow Xray + independent Shadow WARP** path.
- Promotes a destination to Direct only when Shadow WARP fails and the Reserved-IP Direct path succeeds.
- Applies ordinary routing changes live through Xray RoutingService.
- Fails closed: if Shadow WARP is unhealthy, it makes no routing change.
- Keeps user-defined pinned domains out of probing.

## Installation\n\nThe supported 3x-ui/Ubuntu installer is one command; it provisions an independent Shadow WARP identity, verifies it, and does not restart production Xray:\n\n\`\`\`bash\ncurl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply\n\`\`\`\n\nSee the complete [English guide](docs/INSTALL.md) and [راهنمای فارسی](docs/README.fa.md).\n\n## Policy

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

## Compatibility\n\nThe canonical supported panel is [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui). Alireza x-ui was used only for early Xray isolation experiments and is **not** a release target.\n\n## Release requirements

The v1 installer will be a single-command (or short-command) deployment that:

- installs and validates its dependencies;
- creates a fresh, independent WARP identity;
- provisions the Shadow Xray service and local SOCKS listener;
- installs the controller, policy, systemd services, and safe defaults;
- backs up configuration before changes;
- validates Xray configuration before applying it;
- verifies both the Shadow and production paths after installation;
- provides uninstall and recovery instructions;
- includes complete English and Persian documentation.

The production design has already been exercised with live routing updates, rollback checks, Shadow-WARP outage isolation, and stress requests. The public v1 release must also pass clean Ubuntu installation and recovery tests.

## License

Added with the first release.
