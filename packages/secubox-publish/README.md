# 📰 Publishing Platform

Unified publishing dashboard

**Category:** Publishing

## Screenshot

![Publishing Platform](../../docs/screenshots/vm/publish.png)

## Features

- Multi-platform
- Scheduling
- Analytics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-publish
```

## Configuration

Configuration file: `/etc/secubox/publish.toml`

## API Endpoints

- `GET /api/v1/publish/status` - Module status
- `GET /api/v1/publish/health` - Health check

## License

MIT License - CyberMind © 2024-2026
