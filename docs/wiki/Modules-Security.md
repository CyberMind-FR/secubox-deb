# Modules — Security Stack

Security modules for threat detection, prevention, and response.

---

## Overview

| Module | Function | Status |
|--------|----------|--------|
| secubox-crowdsec | IDS/IPS community | ✅ Active |
| secubox-waf | Web Application Firewall | ✅ Active |
| secubox-ipblock | IP blocking | ✅ Active |
| secubox-threats | Threat intelligence | ✅ Active |
| secubox-interceptor | Traffic inspection | ✅ Active |
| secubox-mac-guard | MAC filtering | ✅ Active |
| secubox-cookies | Cookie security | ✅ Active |

---

## secubox-crowdsec

Community-driven IDS/IPS with automatic bouncing.

### Features
- Real-time threat detection
- Community blocklists
- Automatic ban/captcha
- REST API integration

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/crowdsec/status` | Service status |
| GET | `/api/v1/crowdsec/decisions` | Active decisions |
| POST | `/api/v1/crowdsec/ban` | Manual ban |
| DELETE | `/api/v1/crowdsec/unban/{ip}` | Remove ban |

---

## secubox-waf

HAProxy + mitmproxy Web Application Firewall.

### Features
- OWASP ModSecurity CRS
- TLS 1.3 termination
- Request/response inspection
- No bypass mode

### Configuration
```toml
[waf]
enabled = true
mode = "inspect"  # inspect | block | log-only

[waf.rules]
owasp_crs = true
custom_rules = "/etc/secubox/waf/rules.d/"
```

---

## secubox-ipblock

IP-based access control and geoblocking.

### Features
- Country-level blocking
- IP/CIDR blacklists
- Whitelist management
- Tor exit node blocking

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/ipblock/lists` | Active lists |
| POST | `/api/v1/ipblock/block` | Add to blacklist |
| POST | `/api/v1/ipblock/allow` | Add to whitelist |
| GET | `/api/v1/ipblock/geo` | Geo-blocking status |

---

## secubox-threats

Threat intelligence aggregation.

### Sources
- AbuseIPDB
- Emerging Threats
- CrowdSec CTI
- Custom feeds

### Features
- Automatic feed updates
- IOC correlation
- Alert generation

---

## secubox-interceptor

Deep packet inspection and logging.

### Features
- Protocol analysis
- SSL/TLS inspection
- Traffic logging
- Anomaly detection

---

## secubox-mac-guard

MAC address filtering for LAN security.

### Features
- Known device whitelist
- Unknown device alerts
- Automatic quarantine
- DHCP integration

---

## Installation

```bash
# Install all security modules
sudo apt install secubox-crowdsec secubox-waf secubox-ipblock secubox-threats

# Or install meta-package
sudo apt install secubox-security
```

---

## See Also

- [[Modules]] — All modules
- [[Modules-Networking]] — Network modules
- [[Architecture-Security]] — Security model

---

*← Back to [[Home|SecuBox OS]]*
