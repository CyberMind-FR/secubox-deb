# 📻 Web Radio

Internet radio streaming

**Category:** Media

## Screenshot

![Web Radio](../../docs/screenshots/vm/webradio.png)

## Features

- Radio stations
- Recording
- Schedule
- Favorites

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-webradio
```

## Configuration

Configuration file: `/etc/secubox/webradio.toml`

## API Endpoints

- `GET /api/v1/webradio/status` - Module status
- `GET /api/v1/webradio/health` - Health check

## License

MIT License - CyberMind © 2024-2026
