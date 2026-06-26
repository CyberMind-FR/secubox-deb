# 🔥 Vortex Firewall

nftables-based threat enforcement firewall

**Category:** Security

## Screenshot

![Vortex Firewall](../../docs/screenshots/vm/vortex-firewall.png)

## Features

- IP blocklists
- nftables sets
- Threat feeds
- Geo-blocking

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-vortex-firewall
```

## Configuration

Configuration file: `/etc/secubox/vortex-firewall.toml`

## API Endpoints

- `GET /api/v1/vortex-firewall/status` - Module status
- `GET /api/v1/vortex-firewall/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
