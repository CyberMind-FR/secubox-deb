# 🔬 Threat Analyst

AI-powered threat analysis

**Category:** Security

## Screenshot

![Threat Analyst](../../docs/screenshots/vm/threat-analyst.png)

## Features

- ML detection
- Behavioral analysis
- IOC extraction
- Reports

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-threat-analyst
```

## Configuration

Configuration file: `/etc/secubox/threat-analyst.toml`

## API Endpoints

- `GET /api/v1/threat-analyst/status` - Module status
- `GET /api/v1/threat-analyst/health` - Health check

## License

MIT License - CyberMind © 2024-2026
