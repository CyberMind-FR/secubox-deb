# 📱 Device Intelligence

Asset discovery and fingerprinting

**Category:** Monitoring

## Screenshot

![Device Intelligence](../../docs/screenshots/vm/device-intel.png)

## Features

- ARP scanning
- MAC vendor lookup
- OS detection

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-device-intel
```

## Configuration

Configuration file: `/etc/secubox/device-intel.toml`

## API Endpoints

- `GET /api/v1/device-intel/status` - Module status
- `GET /api/v1/device-intel/health` - Health check

## License

MIT License - CyberMind © 2024-2026
