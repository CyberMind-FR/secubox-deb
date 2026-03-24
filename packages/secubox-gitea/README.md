# 🦊 Gitea

Git server (LXC)

**Category:** Services

## Screenshot

![Gitea](../../docs/screenshots/vm/gitea.png)

## Features

- Repositories
- Users
- SSH/HTTP
- LFS

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-gitea
```

## Configuration

Configuration file: `/etc/secubox/gitea.toml`

## API Endpoints

- `GET /api/v1/gitea/status` - Module status
- `GET /api/v1/gitea/health` - Health check

## License

MIT License - CyberMind © 2024-2026
