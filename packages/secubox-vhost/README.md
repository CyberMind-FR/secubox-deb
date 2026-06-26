# 🏗️ Virtual Hosts

Nginx virtual host management

**Category:** Network

## Screenshot

![Virtual Hosts](../../docs/screenshots/vm/vhost.png)

## Features

- Site management
- SSL certificates
- Reverse proxy
- Let's Encrypt

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-vhost
```

## Configuration

Configuration file: `/etc/secubox/vhost.toml`

## API Endpoints

- `GET /api/v1/vhost/status` - Module status
- `GET /api/v1/vhost/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
