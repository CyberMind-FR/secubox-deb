# 🧅 Tor Network

Tor anonymity and hidden services

**Category:** Privacy

## Screenshot

![Tor Network](../../docs/screenshots/vm/tor.png)

## Features

- Circuits
- Hidden services
- Bridges

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-tor
```

## Configuration

Configuration file: `/etc/secubox/tor.toml`

## API Endpoints

- `GET /api/v1/tor/status` - Module status
- `GET /api/v1/tor/health` - Health check

## License

MIT License - CyberMind © 2024-2026
