# 🏗️ Virtual Hosts

Nginx virtual host management

**Category:** Network

## Screenshot

![Virtual Hosts](../../docs/screenshots/vm/vhost.png)

## Features

- Site management
- SSL certificates
- Reverse proxy

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

MIT License - CyberMind © 2024-2026
