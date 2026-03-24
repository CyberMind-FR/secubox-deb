# 🔐 Auth Guardian

Authentication management

**Category:** Security

## Screenshot

![Auth Guardian](../../docs/screenshots/vm/auth.png)

## Features

- OAuth2
- LDAP
- 2FA
- Session management

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-auth
```

## Configuration

Configuration file: `/etc/secubox/auth.toml`

## API Endpoints

- `GET /api/v1/auth/status` - Module status
- `GET /api/v1/auth/health` - Health check

## License

MIT License - CyberMind © 2024-2026
