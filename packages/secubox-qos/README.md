# 📊 QoS Manager

Quality of Service with HTB/VLAN

**Category:** Network

## Screenshot

![QoS Manager](../../docs/screenshots/vm/qos.png)

## Features

- Bandwidth control
- VLAN policies
- 802.1p PCP

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-qos
```

## Configuration

Configuration file: `/etc/secubox/qos.toml`

## API Endpoints

- `GET /api/v1/qos/status` - Module status
- `GET /api/v1/qos/health` - Health check

## License

MIT License - CyberMind © 2024-2026
