# 🎵 Lyrion Music

Music streaming server

**Category:** Media

## Screenshot

![Lyrion Music](../../docs/screenshots/vm/lyrion.png)

## Features

- Music library
- Playlists
- Radio
- Multi-room

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-lyrion
```

## Configuration

Configuration file: `/etc/secubox/lyrion.toml`

## API Endpoints

- `GET /api/v1/lyrion/status` - Module status
- `GET /api/v1/lyrion/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
