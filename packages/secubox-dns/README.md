# 🌍 DNS Server

BIND DNS zone management

**Category:** DNS

## Screenshot

![DNS Server](../../docs/screenshots/vm/dns.png)

## Features

- Zone management
- Records
- DNSSEC

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns
```

## Configuration

Configuration file: `/etc/secubox/dns.toml`

## API Endpoints

- `GET /api/v1/dns/status` - Module status
- `GET /api/v1/dns/health` - Health check

## License

MIT License - CyberMind © 2024-2026
