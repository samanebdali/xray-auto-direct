# Installation and operation (English)

## Scope and safety

Auto-Direct v1 supports Ubuntu 22.04/24.04 servers that already run **x-ui** in the standard layout:

- Xray binary: `/usr/local/x-ui/bin/xray-linux-amd64`
- active config: `/usr/local/x-ui/bin/config.json`
- x-ui SQLite DB: `/etc/x-ui/x-ui.db`
- access log: `/var/log/x-ui/access.log`
- Xray RoutingService: `127.0.0.1:62789`

The active configuration and the x-ui database must both contain a Direct domain rule with `outboundTag: "direct"`. The installer checks this before it writes anything. It does **not** restart or reload x-ui or production Xray.

The install creates a brand-new WARP identity for Shadow. It never imports, reads, or shares the production WARP identity. If requested, primary-WARP bootstrap creates a second, distinct identity for user traffic.

## One-command installation

Review the repository, then run this as root (or prefix with `sudo`):

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply
```

For observation without live promotions:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --dry-run
```

If the panel does not yet have a user WARP outbound, bootstrap it only on a simple route set:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply --bootstrap-primary-warp --inbound-tag YOUR_INBOUND_TAG
```

Bootstrap uses the tag `autodirect-primary-warp`, creates a separate primary identity, validates the full config, applies the live outbound/rules through RoutingService, persists the same change in 3x-ui, and verifies the Xray PID. It refuses balancers, ambiguous catch-all rules, and pre-existing conflicting tags. Re-running it is idempotent.

The installer automatically:

1. checks the live RoutingService and the config/database preconditions;
2. installs small OS prerequisites;
3. downloads a current `wgcf` release and registers an independent WARP account (five bounded retries);
4. generates a root-only Shadow Xray config listening only on `127.0.0.1:20808`;
5. validates the Shadow config with the production Xray binary;
6. starts Shadow and requires a Cloudflare trace showing `warp=on` or `warp=plus`;
7. synchronizes pinned Direct policy, installs/enables the controller, and runs its self-test.

A failed prerequisite aborts safely. It does not fall back to production WARP or Direct for probes.

## Policy

Edit `/etc/xray-auto-direct/policy.json`, then restart **only** the controller:

```bash
sudoedit /etc/xray-auto-direct/policy.json
sudo systemctl restart xray-auto-direct.service
```

- `pinned_direct_suffixes`: enforced as live Direct routes on controller start.
- `manual_direct_suffixes`: same behavior, for destinations you explicitly choose.
- `pinned_warp_suffixes`: never probed or promoted; they remain governed by your pre-existing WARP route.
- A suffix cannot appear in both lists. An invalid policy fails safe: no policy Direct routes are added and the default OpenAI WARP exclusions apply.

No policy change restarts production Xray. When a Direct entry must be applied, the controller validates a temporary config, backs up config and DB, updates the runtime ruleset via RoutingService, checks the production PID, then either commits or rolls back.

## Status and logs

```bash
sudo systemctl status xray-autodirect-shadow.service xray-auto-direct.service
sudo /usr/local/lib/xray-auto-direct/xray-auto-direct.py --selftest
sudo journalctl -u xray-auto-direct.service -u xray-autodirect-shadow.service -n 100 --no-pager
```

A healthy Shadow trace must contain `warp=on` or `warp=plus`. If Shadow fails, the controller skips every probe and promotion (fail-closed). User proxy traffic continues on its separate production path.

## Stop / removal

To stop automation without altering production Xray:

```bash
sudo systemctl disable --now xray-auto-direct.service xray-autodirect-shadow.service
```

Do not delete `/etc/xray-auto-direct` or `/var/lib/xray-auto-direct` until you have reviewed backups and no longer need the independent WARP identity. Routes already promoted before stopping are intentionally left unchanged; automatic deletion could break active destinations. Each live change has config/DB backups under `/var/lib/xray-auto-direct/backups`.

## Security

- Do not commit `shadow.json`, `wgcf-account.toml`, `wgcf-profile.conf`, `policy.json`, or controller state.
- Keep `/etc/xray-auto-direct` and `/var/lib/xray-auto-direct` root-owned.
- The Shadow SOCKS port binds only to loopback and should never be opened in a firewall.
