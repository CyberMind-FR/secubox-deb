# 🛤️ Routing Manager

Static and policy-based routing

**Category:** Network

## Screenshot

![Routing Manager](../../docs/screenshots/vm/routes.png)

## Features

- Static routes
- Policy routing
- Multi-WAN
- Failover

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-routes
```

## Configuration

Configuration file: `/etc/secubox/routes.toml`

## API Endpoints

- `GET /api/v1/routes/status` - Module status
- `GET /api/v1/routes/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
