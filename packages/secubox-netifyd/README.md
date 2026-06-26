# 🔬 Netifyd DPI

Netifyd deep packet inspection

**Category:** Monitoring

## Screenshot

![Netifyd DPI](../../docs/screenshots/vm/netifyd.png)

## Features

- Application detection
- Protocol analysis
- Flow stats
- API

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netifyd
```

## Configuration

Configuration file: `/etc/secubox/netifyd.toml`

## API Endpoints

- `GET /api/v1/netifyd/status` - Module status
- `GET /api/v1/netifyd/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
