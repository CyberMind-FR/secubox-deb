# 💾 Backup Manager

System and LXC backup

**Category:** System

## Screenshot

![Backup Manager](../../docs/screenshots/vm/backup.png)

## Features

- Config backup
- LXC snapshots
- Restore

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-backup
```

## Configuration

Configuration file: `/etc/secubox/backup.toml`

## API Endpoints

- `GET /api/v1/backup/status` - Module status
- `GET /api/v1/backup/health` - Health check

## License

MIT License - CyberMind © 2024-2026
