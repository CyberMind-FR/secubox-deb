# 📦 APT Repository

APT repository management

**Category:** Apps

## Screenshot

![APT Repository](../../docs/screenshots/vm/repo.png)

## Features

- Package management
- GPG signing
- Multi-distro

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-repo
```

## Configuration

Configuration file: `/etc/secubox/repo.toml`

## API Endpoints

- `GET /api/v1/repo/status` - Module status
- `GET /api/v1/repo/health` - Health check

## License

MIT License - CyberMind © 2024-2026
