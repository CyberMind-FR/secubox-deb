# SecuBox Mitmproxy WAF

Web Application Firewall module for SecuBox-Deb with traffic inspection, threat detection, and CrowdSec integration.

**Category:** Security
**Version:** 1.0.0
**License:** Proprietary - CyberMind.fr

## Screenshot

![MITM Proxy](../../docs/screenshots/vm/mitmproxy.png)

## Features

- **LXC-Isolated Proxy** - Mitmproxy runs in dedicated LXC container for security isolation
- **90+ Detection Patterns** - SQLi, XSS, RCE, Log4Shell, path traversal, and more
- **HAProxy Integration** - Transparent inspection for all vhost-routed traffic
- **CrowdSec Auto-ban** - JSONL threat log for automatic IP banning
- **Real-time Dashboard** - WebUI with threat stats, alerts, and rule management
- **Configurable Severity** - Per-category enable/disable and sensitivity tuning
- **Route Synchronization** - Automatic backend routing from HAProxy config

## Architecture

```
                                   SecuBox Mitmproxy WAF
    +---------------------------------------------------------------------------------+
    |                                                                                 |
    |   Internet                                                                      |
    |       |                                                                         |
    |       v                                                                         |
    |  +----------+     +-------------------+     +---------------------------+       |
    |  | HAProxy  |---->| LXC: mitmproxy-waf|---->| Backend Services          |       |
    |  | TLS 1.3  |     |                   |     | (from routes.json)        |       |
    |  +----------+     | +---------------+ |     +---------------------------+       |
    |       |           | | mitmdump      | |                                         |
    |       |           | | + secubox_waf | |                                         |
    |       |           | +-------+-------+ |                                         |
    |       |           |         |         |                                         |
    |       |           +---------+---------+                                         |
    |       |                     |                                                   |
    |       |                     v                                                   |
    |       |           +-------------------+                                         |
    |       |           | /srv/mitmproxy-waf|                                         |
    |       |           |  +-- data/        |                                         |
    |       |           |  |   +-- threats.log  <-- JSONL threat log                  |
    |       |           |  |   +-- routes.json  <-- HAProxy vhost map                 |
    |       |           |  |   +-- stats.json   <-- Detection stats                   |
    |       |           |  +-- addons/      |                                         |
    |       |           |      +-- secubox_waf.py                                     |
    |       |           +-------------------+                                         |
    |       |                     |                                                   |
    |       v                     v                                                   |
    |  +----------+     +-------------------+                                         |
    |  | FastAPI  |     | CrowdSec          |                                         |
    |  | REST API |     | (reads threats.log)                                         |
    |  +----------+     +-------------------+                                         |
    |       |                     |                                                   |
    |       v                     v                                                   |
    |  +----------+     +-------------------+                                         |
    |  | WebUI    |     | nftables Ban      |                                         |
    |  | Dashboard|     | (via bouncer)     |                                         |
    |  +----------+     +-------------------+                                         |
    |                                                                                 |
    +---------------------------------------------------------------------------------+
```

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mitmproxy

# Install LXC container
sudo mitmproxyctl install

# Start the WAF
sudo mitmproxyctl start

# Enable HAProxy integration
curl -X POST http://localhost/api/v1/mitmproxy/haproxy/enable \
  -H "Authorization: Bearer $TOKEN"
```

## API Endpoints

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

### Status and Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitmproxy/health` | Health check (no auth) |
| GET | `/api/v1/mitmproxy/status` | Container and WAF status |
| POST | `/api/v1/mitmproxy/start` | Start WAF container |
| POST | `/api/v1/mitmproxy/stop` | Stop WAF container |
| POST | `/api/v1/mitmproxy/restart` | Restart WAF container |

### Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitmproxy/settings` | Get current configuration |
| POST | `/api/v1/mitmproxy/settings` | Update configuration |

### Threats and Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitmproxy/alerts` | List threats (paginated, filterable) |
| GET | `/api/v1/mitmproxy/alerts/stats` | Aggregated threat statistics |
| POST | `/api/v1/mitmproxy/alerts/clear` | Clear threat log |
| GET | `/api/v1/mitmproxy/bans` | List active CrowdSec bans |
| POST | `/api/v1/mitmproxy/unban` | Remove IP from ban list |

### HAProxy Integration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitmproxy/haproxy/status` | HAProxy WAF integration status |
| POST | `/api/v1/mitmproxy/haproxy/enable` | Enable WAF inspection |
| POST | `/api/v1/mitmproxy/haproxy/disable` | Disable WAF inspection |
| POST | `/api/v1/mitmproxy/haproxy/sync` | Sync routes from HAProxy |
| GET | `/api/v1/mitmproxy/haproxy/routes` | Get current route mappings |

### WAF Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitmproxy/waf/rules` | List rule categories |
| POST | `/api/v1/mitmproxy/waf/rules/toggle` | Enable/disable category |
| GET | `/api/v1/mitmproxy/waf/rules/stats` | Per-category detection stats |

## Configuration

Configuration file: `/etc/secubox/mitmproxy.toml`

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
enabled = false
config_path = "/etc/haproxy/haproxy.cfg"
backend_name = "mitmproxy_waf"

[crowdsec]
enabled = true
threats_log = "/srv/mitmproxy-waf/data/threats.log"

[autoban]
enabled = true
sensitivity = "moderate"    # permissive | moderate | aggressive
ban_duration = "4h"
min_severity = "high"       # low | medium | high | critical

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
moderate_window = 300       # seconds
permissive_count = 5
permissive_window = 3600

[whitelist]
ips = ["127.0.0.1"]

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

## Detection Categories

| Category | Severity | Description | Patterns |
|----------|----------|-------------|----------|
| `sqli` | Critical | SQL Injection attacks | UNION SELECT, OR/AND injection, SLEEP, BENCHMARK |
| `xss` | High | Cross-Site Scripting | Script tags, event handlers, javascript: URIs |
| `cmdi` | Critical | Command Injection | Shell commands via ;, \|, backticks, $() |
| `traversal` | High | Path Traversal | ../, encoded traversal, null bytes |
| `ssrf` | Critical | Server-Side Request Forgery | localhost, internal IPs, AWS metadata |
| `xxe` | Critical | XML External Entity | DOCTYPE, ENTITY declarations |
| `ldap` | High | LDAP Injection | Filter manipulation, wildcards |
| `log4shell` | Critical | Log4j RCE (CVE-2021-44228) | JNDI lookups, nested expressions |
| `scanners` | Medium | Security Scanner Detection | sqlmap, nikto, nuclei, burpsuite |
| `path_scan` | Medium | Sensitive Path Scanning | .env, .git/, wp-admin, config.php |
| `cve_exploits` | Critical | Known CVE Exploits | Spring4Shell, MOVEit, Struts OGNL |
| `rce` | Critical | Remote Code Execution | eval(), exec(), system(), passthru() |
| `voip` | Medium | VoIP Protocol Attacks | SIP INVITE (disabled by default) |
| `xmpp` | Medium | XMPP Protocol Attacks | XMPP stanzas (disabled by default) |

## CLI Commands

```bash
# Container management
mitmproxyctl install          # Create and configure LXC container
mitmproxyctl start            # Start container and mitmproxy
mitmproxyctl stop             # Stop container
mitmproxyctl restart          # Restart container
mitmproxyctl status           # Show container and process status
mitmproxyctl destroy --force  # Remove container (destructive)
mitmproxyctl logs             # Show mitmproxy logs

# Service management
systemctl status secubox-mitmproxy    # API service status
systemctl restart secubox-mitmproxy   # Restart API service
journalctl -u secubox-mitmproxy -f    # Follow API logs
```

## File Locations

| Path | Description |
|------|-------------|
| `/etc/secubox/mitmproxy.toml` | Main configuration file |
| `/srv/mitmproxy-waf/` | WAF data directory |
| `/srv/mitmproxy-waf/data/threats.log` | Threat log (JSONL) |
| `/srv/mitmproxy-waf/data/routes.json` | HAProxy route mappings |
| `/srv/mitmproxy-waf/data/waf-rules.json` | WAF rule definitions |
| `/srv/mitmproxy-waf/data/stats.json` | Detection statistics |
| `/srv/mitmproxy-waf/addons/secubox_waf.py` | Mitmproxy addon |
| `/usr/share/secubox/www/mitmproxy/` | WebUI static files |
| `/usr/lib/secubox/mitmproxy/` | Python API module |
| `/run/secubox/mitmproxy.sock` | Unix socket for API |
| `/var/lib/lxc/mitmproxy-waf/` | LXC container root |
| `/etc/nginx/secubox.d/mitmproxy.conf` | Nginx proxy config |

## WebUI Paths

| Path | Description |
|------|-------------|
| `/mitmproxy/` | Dashboard index |
| `/mitmproxy/status.html` | Status and control page |
| `/mitmproxy/settings.html` | Configuration settings |
| `/mitmproxy/filters.html` | WAF rules and filters |

## CrowdSec Integration

The WAF outputs threats to `/srv/mitmproxy-waf/data/threats.log` in JSONL format:

```json
{"ts":1704067200,"ip":"192.168.1.100","host":"app.example.com","path":"/api/users","method":"GET","category":"sqli","severity":"critical","pattern":"union_select","matched":"UNION SELECT"}
```

CrowdSec acquisition configuration is installed to `/etc/crowdsec/acquis.d/secubox-waf.yaml`:

```yaml
source: file
filenames:
  - /srv/mitmproxy-waf/data/threats.log
labels:
  type: secubox-waf
```

## Dependencies

| Package | Description |
|---------|-------------|
| `secubox-core` | Core library (JWT auth, logging) |
| `secubox-haproxy` | HAProxy TLS frontend |
| `lxc` | Linux Containers |
| `lxc-templates` | LXC container templates |
| `python3-uvicorn` | ASGI server |
| `python3-toml` | TOML configuration parser |
| `secubox-crowdsec` (recommended) | Auto-ban via CrowdSec |

## Security Notes

- The mitmproxy instance runs isolated in an LXC container
- Memory is limited to 256M by default to prevent resource exhaustion
- API runs as `secubox` user with minimal privileges
- Threat log is append-only for audit trail integrity
- HAProxy backup is created before WAF modifications
- Whitelist IPs are never banned regardless of detections

## Troubleshooting

```bash
# Check container status
mitmproxyctl status

# View mitmproxy logs
mitmproxyctl logs

# Check API service
systemctl status secubox-mitmproxy
journalctl -u secubox-mitmproxy --no-pager -n 50

# Test API health
curl -s http://localhost/api/v1/mitmproxy/health

# Verify HAProxy integration
curl -s http://localhost/api/v1/mitmproxy/haproxy/status \
  -H "Authorization: Bearer $TOKEN"

# Check threat log
tail -f /srv/mitmproxy-waf/data/threats.log | jq .

# Verify CrowdSec is reading logs
cscli metrics | grep secubox-waf
```

## License

**Proprietary** - CyberMind.fr

Port Debian bookworm de luci-app-mitmproxy (SecuBox OpenWrt).

Author: Gerald KERMA <devel@cybermind.fr>
Homepage: https://cybermind.fr/secubox
