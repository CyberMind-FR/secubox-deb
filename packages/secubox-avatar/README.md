# 🧑 Avatar Manager

Identity and avatar manager

**Category:** Apps

## Screenshot

![Avatar Manager](../../docs/screenshots/vm/avatar.png)

## Features

- Identity profiles
- Avatar generation
- Per-user assets

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-avatar
```

## Configuration

Configuration file: `/etc/secubox/avatar.toml`

## API Endpoints

- `GET /api/v1/avatar/status` - Module status
- `GET /api/v1/avatar/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
