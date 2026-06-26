# 📊 Grafana

Security metrics dashboards

**Category:** Monitoring

## Screenshot

![Grafana](../../docs/screenshots/vm/grafana.png)

## Features

- Time-series dashboards
- Alerting
- Data sources
- Panels

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-grafana
```

## Configuration

Configuration file: `/etc/secubox/grafana.toml`

## API Endpoints

- `GET /api/v1/grafana/status` - Module status
- `GET /api/v1/grafana/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
