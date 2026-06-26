# 🔎 YaCy

Peer-to-peer search engine

**Category:** Network

## Screenshot

![YaCy](../../docs/screenshots/vm/yacy.png)

## Features

- P2P index
- Crawler
- Private search
- Federation

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-yacy
```

## Configuration

Configuration file: `/etc/secubox/yacy.toml`

## API Endpoints

- `GET /api/v1/yacy/status` - Module status
- `GET /api/v1/yacy/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
