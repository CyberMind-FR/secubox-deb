# 🔒 OSSEC HIDS

OSSEC host-based intrusion detection

**Category:** Security

## Screenshot

![OSSEC HIDS](../../docs/screenshots/vm/ossec.png)

## Features

- Log analysis
- Rootkit detection
- File integrity
- Active response

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ossec
```

## Configuration

Configuration file: `/etc/secubox/ossec.toml`

## API Endpoints

- `GET /api/v1/ossec/status` - Module status
- `GET /api/v1/ossec/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
