# 🛡️ DNS Guard

DNS-based threat protection

**Category:** DNS

## Screenshot

![DNS Guard](../../docs/screenshots/vm/dns-guard.png)

## Features

- Malware blocking
- Phishing protection
- Analytics
- Whitelist

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns-guard
```

## Configuration

Configuration file: `/etc/secubox/dns-guard.toml`

## API Endpoints

- `GET /api/v1/dns-guard/status` - Module status
- `GET /api/v1/dns-guard/health` - Health check

## License

MIT License - CyberMind © 2024-2026
