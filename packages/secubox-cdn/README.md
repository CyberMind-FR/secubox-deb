# 🚀 CDN Cache

Content delivery cache

**Category:** Network

## Screenshot

![CDN Cache](../../docs/screenshots/vm/cdn.png)

## Features

- Cache management
- Purge
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-cdn
```

## Configuration

Configuration file: `/etc/secubox/cdn.toml`

## API Endpoints

- `GET /api/v1/cdn/status` - Module status
- `GET /api/v1/cdn/health` - Health check

## License

MIT License - CyberMind © 2024-2026
