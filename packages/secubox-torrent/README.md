# 🌊 Torrent

BitTorrent client

**Category:** Media

## Screenshot

![Torrent](../../docs/screenshots/vm/torrent.png)

## Features

- Downloads
- RSS
- Remote control
- Bandwidth limits

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-torrent
```

## Configuration

Configuration file: `/etc/secubox/torrent.toml`

## API Endpoints

- `GET /api/v1/torrent/status` - Module status
- `GET /api/v1/torrent/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
