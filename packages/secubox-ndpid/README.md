# 🔬 nDPId

nDPI daemon for traffic analysis

**Category:** Monitoring

## Screenshot

![nDPId](../../docs/screenshots/vm/ndpid.png)

## Features

- Protocol detection
- Flow tracking
- JSON API
- Real-time

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ndpid
```

## Configuration

Configuration file: `/etc/secubox/ndpid.toml`

## API Endpoints

- `GET /api/v1/ndpid/status` - Module status
- `GET /api/v1/ndpid/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
