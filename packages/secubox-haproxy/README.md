# ⚡ HAProxy

Load balancer dashboard

**Category:** Network

## Screenshot

![HAProxy](../../docs/screenshots/vm/haproxy.png)

## Features

- Backend management
- Stats
- ACLs
- SSL termination

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-haproxy
```

## Configuration

Configuration file: `/etc/secubox/haproxy.toml`

## API Endpoints

- `GET /api/v1/haproxy/status` - Module status
- `GET /api/v1/haproxy/health` - Health check

## License

MIT License - CyberMind © 2024-2026
