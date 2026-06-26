# 🎬 Jellyfin

Media server

**Category:** Media

## Screenshot

![Jellyfin](../../docs/screenshots/vm/jellyfin.png)

## Features

- Video streaming
- Live TV
- Transcoding
- Mobile apps

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-jellyfin
```

## Configuration

Configuration file: `/etc/secubox/jellyfin.toml`

## API Endpoints

- `GET /api/v1/jellyfin/status` - Module status
- `GET /api/v1/jellyfin/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
