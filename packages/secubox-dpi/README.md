# 🔬 SecuBox DPI Analytics

Netifyd-backed analytics layer: top apps, top protocols, bandwidth
breakdown, talkers, risks. Sets up `tc mirred` to `ifb0` for inline
inspection. Complements `secubox-netifyd` (daemon lifecycle).

For nDPId-engine analysis with TLS fingerprinting (JA3/JA4), see
`secubox-ndpid` instead.

**Category:** Monitoring

## Screenshot

![Deep Packet Inspection](../../docs/screenshots/vm/dpi.png)

## Features

- Protocol detection
- App identification
- Flow analysis
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dpi
```

## Configuration

Configuration file: `/etc/secubox/dpi.toml`

## API Endpoints

- `GET /api/v1/dpi/status` - Module status
- `GET /api/v1/dpi/health` - Health check

## License

MIT License - CyberMind © 2024-2026
