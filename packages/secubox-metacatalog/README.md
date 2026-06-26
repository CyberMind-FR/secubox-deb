# 📇 Metacatalog

Service catalog and registry

**Category:** Services

## Screenshot

![Metacatalog](../../docs/screenshots/vm/metacatalog.png)

## Features

- Service registry
- Discovery
- Metadata
- Catalog UI

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metacatalog
```

## Configuration

Configuration file: `/etc/secubox/metacatalog.toml`

## API Endpoints

- `GET /api/v1/metacatalog/status` - Module status
- `GET /api/v1/metacatalog/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
