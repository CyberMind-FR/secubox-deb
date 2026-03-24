# 🛡️ Security Operations Center

SOC with world clock, threat map, tickets

**Category:** Dashboard

## Screenshot

![Security Operations Center](../../docs/screenshots/vm/soc.png)

## Features

- World clock
- Threat map
- Ticket system
- P2P intel
- Alerts

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-soc
```

## Configuration

Configuration file: `/etc/secubox/soc.toml`

## API Endpoints

- `GET /api/v1/soc/status` - Module status
- `GET /api/v1/soc/health` - Health check

## License

MIT License - CyberMind © 2024-2026
