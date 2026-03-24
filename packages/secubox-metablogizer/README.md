# 📝 Metablogizer

Static site publisher with Tor

**Category:** Publishing

## Screenshot

![Metablogizer](../../docs/screenshots/vm/metablogizer.png)

## Features

- Static sites
- Tor publishing
- Templates

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metablogizer
```

## Configuration

Configuration file: `/etc/secubox/metablogizer.toml`

## API Endpoints

- `GET /api/v1/metablogizer/status` - Module status
- `GET /api/v1/metablogizer/health` - Health check

## License

MIT License - CyberMind © 2024-2026
