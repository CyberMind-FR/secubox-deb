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
- Talk

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

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
