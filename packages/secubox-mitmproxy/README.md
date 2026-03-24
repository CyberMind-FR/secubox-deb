# 🔍 MITM Proxy

Traffic inspection and WAF proxy

**Category:** Security

## Screenshot

![MITM Proxy](../../docs/screenshots/vm/mitmproxy.png)

## Features

- Traffic inspection
- Request logging
- Auto-ban

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mitmproxy
```

## Configuration

Configuration file: `/etc/secubox/mitmproxy.toml`

## API Endpoints

- `GET /api/v1/mitmproxy/status` - Module status
- `GET /api/v1/mitmproxy/health` - Health check

## License

MIT License - CyberMind © 2024-2026
