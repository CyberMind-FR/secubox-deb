# 📋 Migration Roadmap

OpenWRT to Debian migration tracking

**Category:** Dashboard

## Screenshot

![Migration Roadmap](../../docs/screenshots/vm/roadmap.png)

## Features

- Progress tracking
- Module status
- Category view

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-roadmap
```

## Configuration

Configuration file: `/etc/secubox/roadmap.toml`

## API Endpoints

- `GET /api/v1/roadmap/status` - Module status
- `GET /api/v1/roadmap/health` - Health check

## License

MIT License - CyberMind © 2024-2026
