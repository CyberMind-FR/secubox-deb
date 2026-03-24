# 🔥 Vortex Firewall

nftables threat enforcement

**Category:** Security

## Screenshot

![Vortex Firewall](../../docs/screenshots/vm/vortex-firewall.png)

## Features

- IP blocklists
- nftables sets
- Threat feeds

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

MIT License - CyberMind © 2024-2026
