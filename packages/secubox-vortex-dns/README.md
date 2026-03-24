# 🛡️ Vortex DNS

DNS firewall with RPZ

**Category:** DNS

## Screenshot

![Vortex DNS](../../docs/screenshots/vm/vortex-dns.png)

## Features

- Blocklists
- RPZ
- Threat feeds

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-vortex-dns
```

## Configuration

Configuration file: `/etc/secubox/vortex-dns.toml`

## API Endpoints

- `GET /api/v1/vortex-dns/status` - Module status
- `GET /api/v1/vortex-dns/health` - Health check

## License

MIT License - CyberMind © 2024-2026
