# 🔍 Network Diagnostics

Network troubleshooting tools

**Category:** Network

## Screenshot

![Network Diagnostics](../../docs/screenshots/vm/netdiag.png)

## Features

- Ping/Traceroute
- DNS lookup
- Port scan
- Speed test

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netdiag
```

## Configuration

Configuration file: `/etc/secubox/netdiag.toml`

## API Endpoints

- `GET /api/v1/netdiag/status` - Module status
- `GET /api/v1/netdiag/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
