# 📡 Mesh DNS

Mesh network domain resolution

**Category:** DNS

## Screenshot

![Mesh DNS](../../docs/screenshots/vm/meshname.png)

## Features

- mDNS/Avahi
- Local DNS
- Service discovery
- Mesh integration

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-meshname
```

## Configuration

Configuration file: `/etc/secubox/meshname.toml`

## API Endpoints

- `GET /api/v1/meshname/status` - Module status
- `GET /api/v1/meshname/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
