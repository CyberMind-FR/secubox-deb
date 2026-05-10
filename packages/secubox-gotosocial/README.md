# 🐘 GoToSocial

ActivityPub social server

**Category:** Publishing

## Screenshot

![GoToSocial](../../docs/screenshots/vm/gotosocial.png)

## Features

- Mastodon compatible
- Federation
- Media
- Privacy

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-gotosocial
```

## Configuration

Configuration file: `/etc/secubox/gotosocial.toml`

## API Endpoints

- `GET /api/v1/gotosocial/status` - Module status
- `GET /api/v1/gotosocial/health` - Health check

## License

MIT License - CyberMind © 2024-2026
