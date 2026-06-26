# 🔬 Deep Packet Inspection

DPI with netifyd/nDPId

**Category:** Monitoring

## Screenshot

![Deep Packet Inspection](../../docs/screenshots/vm/dpi.png)

## Features

- Protocol detection
- App identification
- Flow analysis
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dpi
```

## Configuration

Configuration file: `/etc/secubox/dpi.toml`

## API Endpoints

- `GET /api/v1/dpi/status` - Module status
- `GET /api/v1/dpi/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
