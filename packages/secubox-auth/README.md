# 🔐 Auth Guardian

Unified authentication management

**Category:** Security

## Screenshot

![Auth Guardian](../../docs/screenshots/vm/auth.png)

## Features

- OAuth2
- LDAP
- 2FA/TOTP
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

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
