# 🔒 System Hardening

Kernel and system hardening for ANSSI CSPN compliance

**Category:** Security

## Screenshot

![System Hardening](../../docs/screenshots/vm/hardening.png)

## Features

- Sysctl hardening
- Module blacklist
- Security score
- AppArmor

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-hardening
```

## Configuration

Configuration file: `/etc/secubox/hardening.toml`

## API Endpoints

- `GET /api/v1/hardening/status` - Module status
- `GET /api/v1/hardening/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
