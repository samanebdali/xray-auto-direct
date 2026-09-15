# Installation

The public installer is designed for Ubuntu 22.04 hosts running x-ui/Xray.

When the full Shadow bootstrap is released, installation will be one command:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash
```

The current installer and controller are being prepared from the production design. It deliberately refuses to run if the isolated Shadow-WARP service is absent: sharing production WARP with probes would violate the project’s safety model.

After installation, edit only:

```
/etc/xray-auto-direct/policy.json
```

Then run:

```bash
sudo systemctl restart xray-auto-direct
sudo systemctl status xray-auto-direct
```
