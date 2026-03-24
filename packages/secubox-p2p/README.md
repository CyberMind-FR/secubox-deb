# 🔗 P2P Network

Peer-to-peer networking

**Category:** VPN

## Screenshot

![P2P Network](../../docs/screenshots/vm/p2p.png)

## Features

- Direct connections
- NAT traversal
- Encryption

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-p2p
```

## Configuration

Configuration file: `/etc/secubox/p2p.toml`

## API Endpoints

- `GET /api/v1/p2p/status` - Module status
- `GET /api/v1/p2p/health` - Health check

## License

MIT License - CyberMind © 2024-2026
