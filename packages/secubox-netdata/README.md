# 📊 Netdata

Real-time system monitoring

**Category:** Monitoring

## Screenshot

![Netdata](../../docs/screenshots/vm/netdata.png)

## Features

- Metrics
- Alerts
- Charts
- Plugins

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netdata
```

## Configuration

Configuration file: `/etc/secubox/netdata.toml`

## API Endpoints

- `GET /api/v1/netdata/status` - Module status
- `GET /api/v1/netdata/health` - Health check

## License

MIT License - CyberMind © 2024-2026
