# 📡 Mesh DNS

Mesh network domain resolution

**Category:** DNS

## Screenshot

![Mesh DNS](../../docs/screenshots/vm/meshname.png)

## Features

- mDNS/Avahi
- Local DNS
- Service discovery

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

MIT License - CyberMind © 2024-2026
