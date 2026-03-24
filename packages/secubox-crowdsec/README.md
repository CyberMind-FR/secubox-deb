# 🛡️ CrowdSec

Collaborative security engine

**Category:** Security

## Screenshot

![CrowdSec](../../docs/screenshots/vm/crowdsec.png)

## Features

- Decision management
- Alerts
- Bouncers
- Collections

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-crowdsec
```

## Configuration

Configuration file: `/etc/secubox/crowdsec.toml`

## API Endpoints

- `GET /api/v1/crowdsec/status` - Module status
- `GET /api/v1/crowdsec/health` - Health check

## License

MIT License - CyberMind © 2024-2026
