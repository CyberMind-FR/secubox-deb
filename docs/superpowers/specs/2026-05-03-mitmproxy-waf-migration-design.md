<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mitmproxy WAF Migration Design Spec

> **Migration:** secubox-openwrt → secubox-deb
> **Module:** luci-app-mitmproxy + secubox-app-mitmproxy → secubox-mitmproxy
> **Date:** 2026-05-03
> **Session:** 90

---

## Overview

Migrate the mitmproxy WAF module from SecuBox-OpenWrt to SecuBox-DEB. This provides HTTP traffic inspection for HAProxy-hosted services with threat detection and CrowdSec integration for automatic IP banning.

**Scope:** WAF-in mode only (HAProxy backend inspection). Excludes transparent outbound proxy mode.

**Package:** Single unified `secubox-mitmproxy` package containing API, LXC management, threat detection addon, and WebUI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  HAProxy (443/80)                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ backend mitmproxy_waf                                    │   │
│  │   server waf 127.0.0.1:8890                             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LXC Container: mitmproxy-waf                                   │
│  ┌──────────────────┐  ┌─────────────────────────────────────┐ │
│  │ mitmproxy        │  │ secubox_waf.py addon                │ │
│  │ :8890 (proxy)    │──│ - Pattern matching (90+ rules)      │ │
│  │ :8091 (web UI)   │  │ - Severity scoring                  │ │
│  └──────────────────┘  │ - JSONL logging → threats.log       │ │
│                        └─────────────────────────────────────┘ │
│  Bind mounts:                                                   │
│  - /srv/mitmproxy-waf/data → container /data                   │
│  - /srv/mitmproxy-waf/addons → container /addons               │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐    ┌─────────────────────────────────┐
│ /srv/mitmproxy-waf/     │    │ CrowdSec                        │
│   threats.log (JSONL)   │───▶│ acquisition: file source        │
│   routes.json           │    │ scenarios: waf-* parsers        │
│   stats.json (cache)    │    │ → ban via bouncers              │
└─────────────────────────┘    └─────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Real Backends (your services)                                  │
│  - app1.example.com → 192.168.1.10:8080                        │
│  - app2.example.com → 192.168.1.20:3000                        │
└─────────────────────────────────────────────────────────────────┘
```

**Components:**
1. **HAProxy** — Receives HTTPS traffic, routes through WAF backend
2. **LXC Container** — Isolated mitmproxy instance with threat detection addon
3. **secubox_waf.py** — Python addon inside container doing pattern matching
4. **CrowdSec** — Reads threat log, applies bans via existing integration
5. **FastAPI** — External API managing container + serving WebUI

---

## Package Structure

```
packages/secubox-mitmproxy/
├── api/
│   ├── __init__.py
│   ├── main.py              # FastAPI app with all routers
│   └── routers/
│       ├── status.py        # Status, start, stop, restart
│       ├── settings.py      # Configuration CRUD
│       ├── alerts.py        # Threat log, stats, clear
│       ├── haproxy.py       # Enable/disable WAF, route sync
│       └── waf.py           # Rule categories toggle
├── addons/
│   └── secubox_waf.py       # Threat detection addon (inside container)
├── bin/
│   └── mitmproxyctl         # Python CLI for LXC management
├── www/
│   └── mitmproxy/
│       ├── index.html       # Redirect to status
│       ├── status.html      # Dashboard
│       ├── settings.html    # Configuration form
│       └── filters.html     # WAF rule toggles
├── menu.d/
│   └── 500-mitmproxy.json   # Sidebar menu entry
├── crowdsec/
│   └── secubox-waf.yaml     # CrowdSec acquisition config
├── debian/
│   ├── control
│   ├── rules
│   ├── postinst
│   ├── prerm
│   └── secubox-mitmproxy.service
└── README.md
```

---

## API Endpoints

Base path: `/api/v1/mitmproxy`
Socket: `/run/secubox/mitmproxy.sock`

### Status & Control

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/status` | JWT | Container state, stats, threat counts |
| GET | `/settings` | JWT | Current configuration |
| POST | `/settings` | JWT | Update configuration |
| POST | `/start` | JWT | Start LXC container |
| POST | `/stop` | JWT | Stop LXC container |
| POST | `/restart` | JWT | Restart container |

### Threat Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/alerts` | JWT | List threats (paginated, filterable) |
| GET | `/alerts/stats` | JWT | Aggregated stats by category/severity |
| POST | `/alerts/clear` | JWT | Clear threat log |
| GET | `/bans` | JWT | Active bans (from CrowdSec) |
| POST | `/unban` | JWT | Remove ban (via cscli) |

### HAProxy Integration

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/haproxy/status` | JWT | WAF inspection enabled? |
| POST | `/haproxy/enable` | JWT | Route HAProxy through WAF |
| POST | `/haproxy/disable` | JWT | Bypass WAF (direct to backends) |
| POST | `/routes/sync` | JWT | Regenerate routes.json from HAProxy |
| GET | `/routes` | JWT | Current route mappings |

### WAF Rules

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/waf/rules` | JWT | List rule categories with status |
| POST | `/waf/rules/toggle` | JWT | Enable/disable category |
| GET | `/waf/rules/stats` | JWT | Per-category detection counts |

**Total: 18 endpoints**

---

## LXC Container Management

### Container Specification

```
Name:         mitmproxy-waf
Base:         Debian bookworm (lxc-download template)
Architecture: Matches host (amd64 or arm64)
Memory:       256M limit (configurable)
```

### Host Directory Structure

```
/srv/mitmproxy-waf/
├── data/
│   ├── threats.log      # JSONL threat log (CrowdSec reads)
│   ├── routes.json      # HAProxy vhost → backend mapping
│   └── stats.json       # Cached stats for fast API response
├── addons/
│   └── secubox_waf.py   # Threat detection addon
└── config/
    └── mitmproxy.yaml   # mitmproxy internal config
```

### LXC Configuration

```
lxc.mount.entry = /srv/mitmproxy-waf/data data none bind,create=dir 0 0
lxc.mount.entry = /srv/mitmproxy-waf/addons addons none bind,create=dir 0 0
lxc.cgroup2.memory.max = 268435456
```

### CLI Commands (mitmproxyctl)

```bash
mitmproxyctl install   # Create container, install mitmproxy, setup mounts
mitmproxyctl start     # lxc-start + run mitmproxy with addon
mitmproxyctl stop      # lxc-stop
mitmproxyctl status    # lxc-info + process check
mitmproxyctl destroy   # lxc-destroy (requires --force)
mitmproxyctl logs      # Show mitmproxy logs from container
```

### Mitmproxy Startup Command

```bash
mitmproxy --mode upstream:http://127.0.0.1:80 \
          --listen-port 8890 \
          --set web_open_browser=false \
          --set web_port=8091 \
          -s /addons/secubox_waf.py
```

---

## Threat Detection Addon

### File: `secubox_waf.py`

Ported from OpenWrt's `secubox_analytics.py` with path updates for Debian.

### Detection Categories

| Category | Example Patterns | Default Severity |
|----------|------------------|------------------|
| `sqli` | UNION SELECT, OR 1=1, SLEEP(), BENCHMARK() | critical |
| `xss` | `<script>`, onerror=, javascript: | high |
| `cmdi` | ; cat, \| grep, backticks, $(...) | critical |
| `traversal` | ../, %2e%2e%2f, nullbyte variants | high |
| `ssrf` | 10.x.x.x, 192.168.x.x, 127.0.0.1, localhost | critical |
| `xxe` | DOCTYPE, ENTITY, SYSTEM | critical |
| `ldap` | )(, \*, (\|, (&, cn=, uid= | high |
| `log4shell` | ${jndi:, ldap://, rmi://, dns:// | critical |
| `scanners` | sqlmap, nikto, nuclei, burpsuite UA | medium |
| `path_scan` | .env, .git/, /wp-admin, /phpmyadmin | medium |
| `cve_exploits` | Spring4Shell, MOVEit, Log4Shell CVEs | critical |
| `rce` | eval(, exec(, system( in params | critical |
| `voip` | SIP INVITE injection | medium |
| `xmpp` | XMPP stanza injection | medium |

### Addon Structure

```python
from mitmproxy import http
import json, re, time
from pathlib import Path

THREATS_LOG = Path("/data/threats.log")
ROUTES_FILE = Path("/data/routes.json")
RULES_FILE = Path("/data/waf-rules.json")

class SecuBoxWAF:
    def __init__(self):
        self.routes = self._load_routes()
        self.rules = self._load_rules()
        self.stats = {cat: 0 for cat in self.rules}

    def request(self, flow: http.HTTPFlow):
        # 1. Check against all enabled rule categories
        threats = self._check_request(flow)

        # 2. Log any detected threats
        for threat in threats:
            self._log_threat(flow, threat)

        # 3. Route to real backend based on Host header
        host = flow.request.host_header
        if host in self.routes:
            backend_ip, backend_port = self.routes[host]
            flow.request.host = backend_ip
            flow.request.port = backend_port

    def _check_request(self, flow) -> list:
        """Check request against all enabled rule categories."""
        threats = []
        target = f"{flow.request.path}?{flow.request.query}" if flow.request.query else flow.request.path

        for category, rules in self.rules.items():
            if not rules.get("enabled", True):
                continue
            for pattern in rules.get("patterns", []):
                if re.search(pattern["regex"], target, re.IGNORECASE):
                    threats.append({
                        "category": category,
                        "severity": rules.get("severity", "medium"),
                        "pattern": pattern["name"],
                        "matched": re.search(pattern["regex"], target, re.IGNORECASE).group(0)
                    })
                    self.stats[category] += 1
                    break  # One match per category
        return threats

    def _log_threat(self, flow, threat):
        """Write threat to JSONL log for CrowdSec consumption."""
        entry = {
            "ts": time.time(),
            "ip": flow.client_conn.peername[0],
            "host": flow.request.host_header,
            "path": flow.request.path,
            "method": flow.request.method,
            "category": threat["category"],
            "severity": threat["severity"],
            "pattern": threat["pattern"],
            "matched": threat["matched"]
        }
        with THREATS_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")

    def _load_routes(self) -> dict:
        """Load Host → backend mapping."""
        if ROUTES_FILE.exists():
            return json.loads(ROUTES_FILE.read_text())
        return {}

    def _load_rules(self) -> dict:
        """Load WAF rules configuration."""
        if RULES_FILE.exists():
            return json.loads(RULES_FILE.read_text())
        return self._default_rules()

addons = [SecuBoxWAF()]
```

### JSONL Output Format

```json
{"ts":1714761234.5,"ip":"203.0.113.50","host":"app.example.com","path":"/api?id=1 OR 1=1","method":"GET","category":"sqli","severity":"critical","pattern":"or_injection","matched":"OR 1=1"}
```

---

## HAProxy Integration

### Backend Configuration

When WAF is enabled, HAProxy uses this backend:

```haproxy
backend mitmproxy_waf
    mode http
    server waf 127.0.0.1:8890 check
```

### Vhost Routing (Before/After)

**Before (direct):**
```haproxy
use_backend app1_backend if { hdr(host) -i app1.example.com }
```

**After (through WAF):**
```haproxy
use_backend mitmproxy_waf if { hdr(host) -i app1.example.com }
```

### Route Sync Process

`POST /routes/sync`:
1. Read `/etc/haproxy/haproxy.cfg`
2. Extract vhost → backend mappings
3. Resolve backend server IPs/ports
4. Write `/srv/mitmproxy-waf/data/routes.json`
5. Signal mitmproxy to reload addon

### routes.json Format

```json
{
  "app1.example.com": ["192.168.1.10", 8080],
  "app2.example.com": ["192.168.1.20", 3000],
  "*.wildcard.com": ["192.168.1.30", 80]
}
```

### Enable/Disable Flow

**Enable:**
1. Backup current HAProxy config
2. Add `mitmproxy_waf` backend if missing
3. Rewrite vhost rules to use WAF backend
4. Reload HAProxy
5. Sync routes to mitmproxy

**Disable:**
1. Restore original backend routing
2. Reload HAProxy

---

## WebUI

### Pages

| Page | Path | Description |
|------|------|-------------|
| Status | `/mitmproxy/status.html` | Dashboard with stats, threats, controls |
| Settings | `/mitmproxy/settings.html` | Configuration form |
| Filters | `/mitmproxy/filters.html` | WAF rule category toggles |

### Status Dashboard Elements

- Container status indicator (Active/Stopped)
- Threats today count
- Blocked IPs count
- Start/Stop/Restart buttons
- HAProxy integration toggle
- Recent threats table (time, IP, category, path)

### Settings Form Fields

- Container memory limit
- Proxy port (8890)
- Web UI port (8091)
- Auto-ban enabled
- Auto-ban sensitivity (aggressive/moderate/permissive)
- Ban duration
- Whitelist IPs

### Filters Page Elements

- Checkbox per rule category
- Hit count per category
- Save changes button

### Required Includes

```html
<head>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">...</main>
    <script src="/shared/sidebar.js"></script>
</body>
```

---

## Configuration

### File: `/etc/secubox/mitmproxy.toml`

```toml
# SecuBox Mitmproxy WAF Configuration

[container]
name = "mitmproxy-waf"
memory_limit = "256M"
autostart = true

[proxy]
listen_port = 8890
web_port = 8091
web_host = "127.0.0.1"
data_path = "/srv/mitmproxy-waf"

[haproxy]
enabled = true
config_path = "/etc/haproxy/haproxy.cfg"
backend_name = "mitmproxy_waf"

[crowdsec]
enabled = true
threats_log = "/srv/mitmproxy-waf/data/threats.log"

[autoban]
enabled = true
sensitivity = "moderate"
ban_duration = "4h"
min_severity = "high"

[autoban.categories]
sqli = true
xss = true
cmdi = true
traversal = true
ssrf = true
log4shell = true
cve_exploits = true
scanners = false
path_scan = false

[autoban.thresholds]
moderate_count = 3
moderate_window = 300
permissive_count = 5
permissive_window = 3600

[whitelist]
ips = ["127.0.0.1", "192.168.1.0/24"]

[waf_rules]
sqli = true
xss = true
cmdi = true
traversal = true
ssrf = true
xxe = true
ldap = true
log4shell = true
scanners = true
path_scan = true
cve_exploits = true
rce = true
voip = false
xmpp = false
```

### CrowdSec Acquisition

File: `/etc/crowdsec/acquis.d/secubox-waf.yaml`

```yaml
source: file
filenames:
  - /srv/mitmproxy-waf/data/threats.log
labels:
  type: secubox-waf
```

---

## Data Flow

### Request Flow (Normal)

1. Client request → HAProxy :443
2. HAProxy routes to mitmproxy_waf backend (127.0.0.1:8890)
3. mitmproxy receives, secubox_waf.py addon inspects
4. No threat detected → continue
5. Addon reads routes.json, finds backend for Host header
6. mitmproxy forwards to real backend
7. Response flows back: backend → mitmproxy → HAProxy → client

### Threat Detection Flow

1. Request matches pattern (e.g., "OR 1=1")
2. Addon logs to /srv/mitmproxy-waf/data/threats.log
3. Request still forwarded (logging, not blocking)
4. CrowdSec acquisition reads threats.log
5. CrowdSec scenario evaluates threshold
6. If exceeded → CrowdSec creates ban decision
7. CrowdSec bouncer blocks IP via nftables

### Stats Cache Flow

1. Background task runs every 60s
2. Reads threats.log, aggregates by category/severity
3. Writes /srv/mitmproxy-waf/data/stats.json
4. API GET /status returns cached stats instantly

---

## File Locations

| File | Purpose |
|------|---------|
| `/etc/secubox/mitmproxy.toml` | Configuration |
| `/srv/mitmproxy-waf/data/threats.log` | JSONL threat log |
| `/srv/mitmproxy-waf/data/routes.json` | Host → backend mapping |
| `/srv/mitmproxy-waf/data/stats.json` | Cached statistics |
| `/srv/mitmproxy-waf/data/waf-rules.json` | Rule definitions |
| `/srv/mitmproxy-waf/addons/secubox_waf.py` | Detection addon |
| `/run/secubox/mitmproxy.sock` | FastAPI Unix socket |
| `/var/lib/lxc/mitmproxy-waf/` | LXC container root |
| `/etc/crowdsec/acquis.d/secubox-waf.yaml` | CrowdSec acquisition |

---

## Menu Integration

File: `menu.d/500-mitmproxy.json`

```json
{
  "id": "mitmproxy",
  "name": "WAF",
  "icon": "🛡️",
  "path": "/mitmproxy/",
  "category": "security",
  "order": 500,
  "description": "Web Application Firewall"
}
```

---

## Dependencies

### Debian Packages

```
Depends: secubox-core (>= 1.0),
         secubox-haproxy,
         lxc,
         lxc-templates,
         python3-uvicorn,
         python3-toml
Recommends: secubox-crowdsec
```

### Inside LXC Container

- mitmproxy (pip install)
- python3

---

## Systemd Service

File: `debian/secubox-mitmproxy.service`

```ini
[Unit]
Description=SecuBox Mitmproxy WAF API
After=network.target secubox-core.service lxc.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/mitmproxy
ExecStart=/usr/bin/uvicorn api.main:app \
    --uds /run/secubox/mitmproxy.sock \
    --log-level warning
ExecStartPost=/bin/chmod 660 /run/secubox/mitmproxy.sock
Restart=on-failure
RestartSec=5

PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/secubox /srv/mitmproxy-waf /var/lib/lxc /etc/secubox

[Install]
WantedBy=multi-user.target
```

---

## Testing Checklist

- [ ] Container creates successfully (`mitmproxyctl install`)
- [ ] Container starts/stops (`mitmproxyctl start/stop`)
- [ ] API health endpoint responds
- [ ] HAProxy enable routes through WAF
- [ ] Threat detection logs to threats.log
- [ ] CrowdSec reads and bans attackers
- [ ] WebUI status page loads with sidebar
- [ ] WebUI settings saves to TOML
- [ ] WebUI filters toggles rule categories
- [ ] Route sync generates correct routes.json

---

## Out of Scope

- Transparent outbound proxy (mitmproxy-out)
- nftables TPROXY mode
- WAN protection mode
- Direct nftables banning (use CrowdSec)
- Certificate pinning bypass
