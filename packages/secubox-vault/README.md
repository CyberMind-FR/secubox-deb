# 🔐 Secret Vault

Secrets and credentials management

**Category:** Privacy

## Screenshot

![Secret Vault](../../docs/screenshots/vm/vault.png)

## Features

- Encrypted storage
- Access control
- Rotation
- Audit

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-vault
```

## Configuration

Configuration file: `/etc/secubox/vault.toml`

## API Endpoints

- `GET /api/v1/vault/status` - Module status
- `GET /api/v1/vault/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
