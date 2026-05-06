# 🔥 SecuBox Web Application Firewall

LXC-contained mitmproxy WAF for HTTP/HTTPS traffic inspection.

**Category:** Security
**Version:** 1.1.0
**License:** CMSD-1.0 (Source-Disclosed)

## Architecture

```
HAProxy (443/9443) → mitmproxy LXC (10.100.0.60:8080) → Backend Services
                           ↓
                    X-SecuBox-WAF: inspected
```

All traffic passes through the mitmproxy WAF container for deep packet inspection before reaching backend services.

## Screenshot

![Web Application Firewall](../../docs/screenshots/vm/waf.png)

## Features

- **LXC Container Isolation** - mitmproxy runs in isolated container (10.100.0.60)
- **Host-based Routing** - Routes requests via `haproxy-routes.json`
- **Traffic Tagging** - Adds `X-SecuBox-WAF: inspected` header
- **300+ Security Rules** - OWASP and custom threat detection
- **CrowdSec Integration** - Centralized banning
- **wafctl Control Script** - Easy management via CLI

## Installation

```bash
# Install package
sudo apt install secubox-waf

# Install mitmproxy LXC container
sudo wafctl install

# Start the WAF
sudo wafctl start
```

## wafctl Commands

```bash
wafctl status       # Show WAF status (JSON)
wafctl components   # List WAF components
wafctl install      # Install mitmproxy LXC container
wafctl start        # Start WAF container and service
wafctl stop         # Stop WAF service
wafctl restart      # Restart WAF
wafctl routes       # Show HAProxy routes config
wafctl add-route <domain> <ip> <port>  # Add a route
wafctl reload       # Reload mitmproxy configuration
wafctl logs [n]     # Show last n log lines
wafctl test [host]  # Test WAF connectivity
```

## Configuration

### HAProxy Routes

Edit `/srv/mitmproxy/haproxy-routes.json` in the container:

```json
{
  "gitea.example.com": ["127.0.0.1", 3000],
  "nextcloud.example.com": ["10.100.0.10", 80]
}
```

Or use wafctl:

```bash
wafctl add-route gitea.example.com 127.0.0.1 3000
wafctl reload
```

### WAF Rules

Rules configuration: `/etc/secubox/waf.toml`

## API Endpoints

- `GET /api/v1/waf/status` - Module status
- `GET /api/v1/waf/health` - Health check
- `GET /api/v1/waf/routes` - Current routes
- `POST /api/v1/waf/routes` - Add/update route

## Network

| Component | IP/Port |
|-----------|---------|
| mitmproxy LXC | 10.100.0.60 |
| Proxy port | 8080 |
| Bridge | br-lxc |

## License

SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma
https://cybermind.fr
