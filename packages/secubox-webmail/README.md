# 💌 Webmail

Roundcube/SOGo webmail

**Category:** Email

## Screenshot

![Webmail](../../docs/screenshots/vm/webmail.png)

## Features

- Web interface
- Address book
- Calendar

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-webmail
```

## Configuration

Configuration file: `/etc/secubox/webmail.toml`

## API Endpoints

- `GET /api/v1/webmail/status` - Module status
- `GET /api/v1/webmail/health` - Health check

## License

MIT License - CyberMind © 2024-2026
