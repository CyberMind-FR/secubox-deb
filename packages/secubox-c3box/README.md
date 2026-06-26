# 📦 Services Portal

C3Box services portal

**Category:** Services

## Screenshot

![Services Portal](../../docs/screenshots/vm/c3box.png)

## Features

- Service links
- Status overview
- Quick access
- Categories

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-c3box
```

## Configuration

Configuration file: `/etc/secubox/c3box.toml`

## API Endpoints

- `GET /api/v1/c3box/status` - Module status
- `GET /api/v1/c3box/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
