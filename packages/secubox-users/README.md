# 👥 User Management

Unified identity management

**Category:** Access

## Screenshot

![User Management](../../docs/screenshots/vm/users.png)

## Features

- User CRUD
- Groups
- Service provisioning

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-users
```

## Configuration

Configuration file: `/etc/secubox/users.toml`

## API Endpoints

- `GET /api/v1/users/status` - Module status
- `GET /api/v1/users/health` - Health check

## License

MIT License - CyberMind © 2024-2026
