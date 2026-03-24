# 🏠 SecuBox Hub

Central dashboard and control center

**Category:** Dashboard

## Screenshot

![SecuBox Hub](../../docs/screenshots/vm/hub.png)

## Features

- System overview
- Service monitoring
- Quick actions
- Metrics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-hub
```

## Configuration

Configuration file: `/etc/secubox/hub.toml`

## API Endpoints

- `GET /api/v1/hub/status` - Module status
- `GET /api/v1/hub/health` - Health check

## License

MIT License - CyberMind © 2024-2026
