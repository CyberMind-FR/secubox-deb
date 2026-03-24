# 🔥 Web Application Firewall

WAF with 300+ security rules

**Category:** Security

## Screenshot

![Web Application Firewall](../../docs/screenshots/vm/waf.png)

## Features

- OWASP rules
- Custom rules
- CrowdSec integration

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-waf
```

## Configuration

Configuration file: `/etc/secubox/waf.toml`

## API Endpoints

- `GET /api/v1/waf/status` - Module status
- `GET /api/v1/waf/health` - Health check

## License

MIT License - CyberMind © 2024-2026
