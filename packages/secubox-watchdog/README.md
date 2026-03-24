# 👁️ Watchdog

Service and container monitoring

**Category:** Monitoring

## Screenshot

![Watchdog](../../docs/screenshots/vm/watchdog.png)

## Features

- Health checks
- Auto-restart
- Alerts

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-watchdog
```

## Configuration

Configuration file: `/etc/secubox/watchdog.toml`

## API Endpoints

- `GET /api/v1/watchdog/status` - Module status
- `GET /api/v1/watchdog/health` - Health check

## License

MIT License - CyberMind © 2024-2026
