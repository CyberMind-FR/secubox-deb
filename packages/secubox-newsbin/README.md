# 📰 Newsbin

Usenet/NNTP client

**Category:** Media

## Screenshot

![Newsbin](../../docs/screenshots/vm/newsbin.png)

## Features

- NZB downloads
- Auto-processing
- Search
- Categories

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-newsbin
```

## Configuration

Configuration file: `/etc/secubox/newsbin.toml`

## API Endpoints

- `GET /api/v1/newsbin/status` - Module status
- `GET /api/v1/newsbin/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
