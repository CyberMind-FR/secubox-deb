# 📶 Modem Manager

3G/4G/5G modem management

**Category:** Network

## Screenshot

![Modem Manager](../../docs/screenshots/vm/modem.png)

## Features

- Connection status
- Signal strength
- SMS
- Failover

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-modem
```

## Configuration

Configuration file: `/etc/secubox/modem.toml`

## API Endpoints

- `GET /api/v1/modem/status` - Module status
- `GET /api/v1/modem/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
