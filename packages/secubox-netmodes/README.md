# 🌐 Network Modes

Network topology configuration

**Category:** Network

## Screenshot

![Network Modes](../../docs/screenshots/vm/netmodes.png)

## Features

- Router mode
- Bridge mode
- AP mode
- VLAN

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netmodes
```

## Configuration

Configuration file: `/etc/secubox/netmodes.toml`

## API Endpoints

- `GET /api/v1/netmodes/status` - Module status
- `GET /api/v1/netmodes/health` - Health check

## License

MIT License - CyberMind © 2024-2026
