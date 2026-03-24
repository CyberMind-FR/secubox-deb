# ☁️ Nextcloud

File sync (LXC)

**Category:** Services

## Screenshot

![Nextcloud](../../docs/screenshots/vm/nextcloud.png)

## Features

- File sync
- WebDAV
- CalDAV
- CardDAV

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-nextcloud
```

## Configuration

Configuration file: `/etc/secubox/nextcloud.toml`

## API Endpoints

- `GET /api/v1/nextcloud/status` - Module status
- `GET /api/v1/nextcloud/health` - Health check

## License

MIT License - CyberMind © 2024-2026
