# ⚙️ Admin Panel

System administration panel

**Category:** Dashboard

## Screenshot

![Admin Panel](../../docs/screenshots/vm/admin.png)

## Features

- User management
- System config
- Logs
- Diagnostics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-admin
```

## Configuration

Configuration file: `/etc/secubox/admin.toml`

## API Endpoints

- `GET /api/v1/admin/status` - Module status
- `GET /api/v1/admin/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
