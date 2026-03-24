# 🎬 Media Flow

Media traffic analytics

**Category:** Monitoring

## Screenshot

![Media Flow](../../docs/screenshots/vm/mediaflow.png)

## Features

- Stream detection
- Bandwidth usage
- Protocol analysis

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mediaflow
```

## Configuration

Configuration file: `/etc/secubox/mediaflow.toml`

## API Endpoints

- `GET /api/v1/mediaflow/status` - Module status
- `GET /api/v1/mediaflow/health` - Health check

## License

MIT License - CyberMind © 2024-2026
