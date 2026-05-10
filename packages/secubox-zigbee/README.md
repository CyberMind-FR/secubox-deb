# 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Category:** IoT

## Screenshot

![Zigbee Gateway](../../docs/screenshots/vm/zigbee.png)

## Features

- Device pairing
- MQTT
- Groups
- OTA updates

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-zigbee
```

## Configuration

Configuration file: `/etc/secubox/zigbee.toml`

## API Endpoints

- `GET /api/v1/zigbee/status` - Module status
- `GET /api/v1/zigbee/health` - Health check

## License

MIT License - CyberMind © 2024-2026
