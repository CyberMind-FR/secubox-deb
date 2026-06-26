# 📞 VoIP Server

Asterisk/FreePBX VoIP

**Category:** Communication

## Screenshot

![VoIP Server](../../docs/screenshots/vm/voip.png)

## Features

- Extensions
- Trunks
- IVR
- Voicemail

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-voip
```

## Configuration

Configuration file: `/etc/secubox/voip.toml`

## API Endpoints

- `GET /api/v1/voip/status` - Module status
- `GET /api/v1/voip/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
