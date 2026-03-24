# 📈 Traffic Shaping

TC/CAKE traffic shaping

**Category:** Network

## Screenshot

![Traffic Shaping](../../docs/screenshots/vm/traffic.png)

## Features

- Per-interface QoS
- CAKE algorithm
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-traffic
```

## Configuration

Configuration file: `/etc/secubox/traffic.toml`

## API Endpoints

- `GET /api/v1/traffic/status` - Module status
- `GET /api/v1/traffic/health` - Health check

## License

MIT License - CyberMind © 2024-2026
