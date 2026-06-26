# 🔗 WireGuard VPN

Modern VPN with kernel integration

**Category:** VPN

## Screenshot

![WireGuard VPN](../../docs/screenshots/vm/wireguard.png)

## Features

- Peer management
- QR codes
- Traffic stats
- Multi-tunnel

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-wireguard
```

## Configuration

Configuration file: `/etc/secubox/wireguard.toml`

## API Endpoints

- `GET /api/v1/wireguard/status` - Module status
- `GET /api/v1/wireguard/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
