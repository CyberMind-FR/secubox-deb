# 📜 Certificate Manager

ACME / TLS certificate manager

**Category:** Security

## Screenshot

![Certificate Manager](../../docs/screenshots/vm/certs.png)

## Features

- ACME issuance
- Renewal
- SAN / wildcard
- Inventory

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-certs
```

## Configuration

Configuration file: `/etc/secubox/certs.toml`

## API Endpoints

- `GET /api/v1/certs/status` - Module status
- `GET /api/v1/certs/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
