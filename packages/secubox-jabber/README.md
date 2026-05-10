# 💬 Jabber/XMPP

XMPP messaging server

**Category:** Email

## Screenshot

![Jabber/XMPP](../../docs/screenshots/vm/jabber.png)

## Features

- Chat
- Groups
- File transfer
- Federation

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-jabber
```

## Configuration

Configuration file: `/etc/secubox/jabber.toml`

## API Endpoints

- `GET /api/v1/jabber/status` - Module status
- `GET /api/v1/jabber/health` - Health check

## License

MIT License - CyberMind © 2024-2026
