# 📧 Mail Server

Postfix/Dovecot mail server

**Category:** Email

## Screenshot

![Mail Server](../../docs/screenshots/vm/mail.png)

## Features

- Domains
- Mailboxes
- DKIM
- SpamAssassin
- ClamAV

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mail
```

## Configuration

Configuration file: `/etc/secubox/mail.toml`

## API Endpoints

- `GET /api/v1/mail/status` - Module status
- `GET /api/v1/mail/health` - Health check

## License

MIT License - CyberMind © 2024-2026
