# 👀 Glances

System monitoring dashboard

**Category:** Monitoring

## Screenshot

![Glances](../../docs/screenshots/vm/glances.png)

## Features

- CPU/Memory
- Disk/Network
- Docker
- Web UI

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-glances
```

## Configuration

Configuration file: `/etc/secubox/glances.toml`

## API Endpoints

- `GET /api/v1/glances/status` - Module status
- `GET /api/v1/glances/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
