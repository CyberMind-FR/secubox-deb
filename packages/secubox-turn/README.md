# 🔄 TURN Server

TURN/STUN relay server

**Category:** Communication

## Screenshot

![TURN Server](../../docs/screenshots/vm/turn.png)

## Features

- NAT traversal
- WebRTC
- TLS
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-turn
```

## Configuration

Configuration file: `/etc/secubox/turn.toml`

## API Endpoints

- `GET /api/v1/turn/status` - Module status
- `GET /api/v1/turn/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
