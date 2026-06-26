# 🔐 MAC Guard

MAC address access control

**Category:** Security

## Screenshot

![MAC Guard](../../docs/screenshots/vm/mac-guard.png)

## Features

- MAC whitelist/blacklist
- Auto-discovery
- Alerts
- VLAN binding

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mac-guard
```

## Configuration

Configuration file: `/etc/secubox/mac-guard.toml`

## API Endpoints

- `GET /api/v1/mac-guard/status` - Module status
- `GET /api/v1/mac-guard/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
