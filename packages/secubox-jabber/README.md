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

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
