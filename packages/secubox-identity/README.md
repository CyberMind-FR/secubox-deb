# 🪪 Identity Provider

SAML/OIDC identity provider

**Category:** Access

## Screenshot

![Identity Provider](../../docs/screenshots/vm/identity.png)

## Features

- SAML 2.0
- OpenID Connect
- Federation
- SSO

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-identity
```

## Configuration

Configuration file: `/etc/secubox/identity.toml`

## API Endpoints

- `GET /api/v1/identity/status` - Module status
- `GET /api/v1/identity/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
