# SecuBox-Wazuh

**SIEM (Security Information and Event Management) Integration Module**

Comprehensive security monitoring and threat detection for SecuBox through Wazuh integration. This module provides unified management of Wazuh agents and managers, real-time alert viewing, file integrity monitoring, rootkit detection, and advanced security analytics.

---

## Overview

`secubox-wazuh` is a FastAPI-based REST interface for Wazuh SIEM functionality on Debian-based SecuBox systems. It exposes Wazuh management capabilities via HTTP API, enabling centralized security monitoring, alert aggregation, and agent management through the SecuBox dashboard.

**Deployment**: Unix socket (`/run/secubox/wazuh.sock`) via systemd service
**Frontend**: HTML5 dashboard with real-time alert feeds
**Backend**: Python 3.11+ FastAPI

---

## Features

- **Dual-Mode Operation**: Supports both Wazuh manager (central server) and agent (monitored endpoint)
- **Real-Time Alert Monitoring**: View and filter security alerts with severity levels
- **Alert Statistics**: Aggregate alerts by severity level, detection rule, and time windows
- **Agent Management**: Register, start, stop, and restart Wazuh agents
- **Manager Control**: Start, stop, and restart Wazuh manager service
- **Agent Discovery**: List connected agents (manager mode)
- **File Integrity Monitoring (FIM)**: Syscheck status and monitored file inventory
- **Rootkit Detection**: Rootcheck scan status and results
- **Detection Rules**: List active detection rule files
- **Log Decoders**: View available log parsing decoders
- **Service Logs**: Stream Wazuh system logs in real-time
- **Health Checks**: Service availability and version reporting

---

## API Endpoints

All endpoints are prefixed with `/api/v1/wazuh/` when accessed through nginx reverse proxy.

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/status` | Wazuh operational status (mode, version, services) |

### Alerts Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List recent alerts (supports `count` and `level` filters) |
| `GET` | `/alerts/stats` | Alert statistics aggregated by severity and rule |
| `GET` | `/alerts/{alert_id}` | Retrieve specific alert by ID |

### Agent Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/agents` | List connected agents (manager mode only) |
| `POST` | `/agent/start` | Start Wazuh agent service |
| `POST` | `/agent/stop` | Stop Wazuh agent service |
| `POST` | `/agent/restart` | Restart Wazuh agent service |
| `POST` | `/agent/register` | Register agent with Wazuh manager |

### Manager Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/manager/start` | Start Wazuh manager service |
| `POST` | `/manager/stop` | Stop Wazuh manager service |
| `POST` | `/manager/restart` | Restart Wazuh manager service |

### Monitoring & Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/syscheck` | File integrity monitoring status and monitored files |
| `GET` | `/rootcheck` | Rootkit detection scan status |
| `GET` | `/rules` | List active detection rule XML files |
| `GET` | `/decoders` | List available log parser decoders |
| `GET` | `/logs` | Stream Wazuh system logs (supports `lines` parameter) |

---

## Configuration

### Environment Variables

```bash
WAZUH_API_URL        # Wazuh API endpoint (default: https://127.0.0.1:55000)
WAZUH_USER           # Wazuh API username (default: wazuh)
WAZUH_PASS           # Wazuh API password (default: wazuh)
```

**Note**: Environment variables must be set in the systemd service environment or system-wide shell configuration.

### System Configuration Files

| Path | Purpose |
|------|---------|
| `/var/ossec/etc/ossec.conf` | Wazuh configuration (manager/agent) |
| `/var/ossec/etc/client.keys` | Agent authentication credentials |
| `/var/ossec/logs/alerts/alerts.json` | Alert log (JSON format) |
| `/var/ossec/logs/ossec.log` | Wazuh system log |
| `/var/ossec/ruleset/rules/` | Detection rule definitions (XML) |
| `/var/ossec/ruleset/decoders/` | Log parser decoders (XML) |

### Nginx Reverse Proxy

The module is exposed via nginx with the following configuration:

```nginx
location /api/v1/wazuh/ {
    proxy_pass http://unix:/run/secubox/wazuh.sock;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /wazuh/ {
    alias /usr/share/secubox/www/wazuh/;
    try_files $uri $uri/ /wazuh/index.html;
}
```

---

## Dependencies

### Debian Packages

```
python3              # Python runtime
python3-fastapi     # Web framework
python3-uvicorn     # ASGI server
secubox-core        # SecuBox shared library
wazuh-agent         # (Recommended) Agent for endpoint monitoring
wazuh-manager       # (Recommended) Central manager for multi-agent setup
```

### Python Dependencies (FastAPI)

- `fastapi` >= 0.100.0
- `uvicorn` >= 0.23.0
- `pydantic` >= 2.0.0
- `requests` >= 2.31.0

### System Dependencies

- `systemd` (for service management)
- `wazuh-control` utility (for version/status queries)
- `agent-auth` utility (for agent registration)
- `agent_control` utility (for agent listing)
- `syscheck_control` utility (for FIM status)
- `rootcheck_control` utility (for rootkit detection)

---

## Installation

### Via APT (Debian Package)

```bash
sudo apt update
sudo apt install secubox-wazuh
```

The package automatically:
- Installs Python dependencies
- Creates systemd service `secubox-wazuh.service`
- Configures nginx reverse proxy
- Enables and starts the service

### Manual Installation (Development)

```bash
# Clone repository
git clone https://github.com/gkerma/secubox-deb.git
cd secubox-deb/packages/secubox-wazuh

# Install dependencies
pip install fastapi uvicorn pydantic requests

# Run API locally (development)
uvicorn api.main:app --reload --uds /tmp/wazuh.sock
```

---

## Usage Examples

### Check Service Status

```bash
# Via systemctl
systemctl status secubox-wazuh

# Via API
curl http://localhost/api/v1/wazuh/status
```

### Get Recent Alerts

```bash
# Last 50 alerts
curl http://localhost/api/v1/wazuh/alerts

# Last 100 alerts with severity >= 5
curl "http://localhost/api/v1/wazuh/alerts?count=100&level=5"
```

### Alert Statistics

```bash
# Aggregate statistics: by level, by rule, top 10 rules, 24h count
curl http://localhost/api/v1/wazuh/alerts/stats
```

### Start Wazuh Agent

```bash
curl -X POST http://localhost/api/v1/wazuh/agent/start
```

### Register Agent with Manager

```bash
curl -X POST http://localhost/api/v1/wazuh/agent/register \
  -H "Content-Type: application/json" \
  -d '{
    "manager_ip": "192.168.1.100",
    "agent_name": "endpoint-01",
    "groups": ["linux", "production"]
  }'
```

### List Connected Agents (Manager Mode)

```bash
curl http://localhost/api/v1/wazuh/agents
```

### File Integrity Monitoring Status

```bash
curl http://localhost/api/v1/wazuh/syscheck
```

### Get System Logs

```bash
# Last 50 log lines
curl "http://localhost/api/v1/wazuh/logs?lines=50"
```

### List Detection Rules

```bash
curl http://localhost/api/v1/wazuh/rules
```

---

## File Structure

```
secubox-wazuh/
├── api/
│   ├── __init__.py
│   └── main.py                          # FastAPI application
├── debian/
│   ├── control                          # Package metadata
│   ├── secubox-wazuh.service           # systemd unit
│   ├── rules                            # Debian debhelper rules
│   └── secubox-wazuh/
│       ├── etc/nginx/secubox.d/wazuh.conf
│       ├── usr/lib/secubox/wazuh/api/main.py
│       └── usr/lib/systemd/system/secubox-wazuh.service
├── menu.d/
│   └── 951-wazuh.json                  # Dashboard menu entry
├── nginx/
│   └── wazuh.conf                      # nginx configuration snippet
├── www/
│   └── wazuh/
│       └── index.html                  # Frontend dashboard
└── README.md                            # This file
```

---

## Data Flow

```
┌──────────────────┐
│  Wazuh Manager   │
│  (OSSEC logs)    │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│  /var/ossec/logs/alerts/         │
│  (alerts.json, ossec.log)        │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  FastAPI Backend                 │
│  (api/main.py)                   │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Unix Socket                     │
│  (/run/secubox/wazuh.sock)       │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  nginx Reverse Proxy             │
│  (location /api/v1/wazuh/)       │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Frontend Dashboard              │
│  (HTML5 @ /wazuh/)              │
└──────────────────────────────────┘
```

---

## Alert Response Format

```json
{
  "timestamp": "2025-04-08T14:30:45.123Z",
  "id": "1712594445123-001",
  "agent": {
    "id": "001",
    "name": "endpoint-01",
    "ip": "192.168.1.50"
  },
  "manager": {
    "name": "secubox-manager"
  },
  "rule": {
    "id": "5710",
    "level": 3,
    "description": "Connection attempt",
    "groups": ["network", "connection_attempt"]
  },
  "data": {
    "src_ip": "192.168.1.200",
    "dest_ip": "192.168.1.100",
    "dest_port": "22",
    "protocol": "TCP"
  }
}
```

---

## Status Response Format

```json
{
  "mode": "manager|agent|none",
  "version": "4.7.0",
  "manager_running": true,
  "agent_running": false,
  "agent": {
    "id": "001",
    "name": "endpoint-prod",
    "ip": "192.168.1.50"
  },
  "services": {
    "wazuh-monitord": "running",
    "wazuh-logcollector": "running",
    "wazuh-remoted": "running"
  }
}
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u secubox-wazuh -n 50 -f

# Verify Wazuh binaries exist
ls -la /var/ossec/bin/

# Check socket permissions
ls -la /run/secubox/wazuh.sock
```

### Alerts Not Appearing

```bash
# Verify alerts.json exists
ls -la /var/ossec/logs/alerts/alerts.json

# Check Wazuh manager status
systemctl status wazuh-manager

# Verify agent connectivity (on manager)
/var/ossec/bin/agent_control -l
```

### Agent Registration Fails

```bash
# Check manager IP is reachable
ping <manager_ip>

# Verify manager is accepting connections
netstat -tuln | grep 1514  # Wazuh agent port

# Review registration logs
journalctl -u secubox-wazuh -n 100
```

### Permission Denied Errors

```bash
# Ensure secubox-wazuh service runs with sufficient privileges
systemctl show secubox-wazuh -p User

# Check Wazuh directory ownership
ls -la /var/ossec/
```

---

## Security Considerations

### Secrets Management

- **Never** commit Wazuh credentials to version control
- Set `WAZUH_USER` and `WAZUH_PASS` via environment variables only
- Consider using `/etc/secubox/secrets/wazuh.env` with `chmod 600` in production
- Load secrets in systemd service with `EnvironmentFile=/etc/secubox/secrets/wazuh.env`

### Authentication

- Wazuh API credentials must be rotated regularly
- API socket is restricted to localhost via Unix socket transport
- Nginx reverse proxy enforces JWT authentication at the SecuBox layer

### Audit Logging

All security decisions (alerts, agent registration, service restarts) are automatically logged to:
- `/var/log/secubox/audit.log` (append-only)
- `journalctl -u secubox-wazuh`

---

## Dashboard Menu

The Wazuh module is registered in the SecuBox dashboard with:

```json
{
  "id": "wazuh",
  "name": "Wazuh SIEM",
  "icon": "🛡️",
  "path": "/wazuh/",
  "category": "security",
  "order": 951,
  "description": "Security monitoring and alerts"
}
```

---

## Performance Notes

- Alert log parsing loads last 1000 entries in memory for statistics
- Statistics calculation is O(n) and may be slow with large alert volumes
- Consider implementing background cache refresh for high-volume deployments
- Monitor `/var/ossec/logs/alerts/alerts.json` file size (archive when > 1GB)

---

## Related Modules

- **secubox-core**: Shared authentication and configuration library
- **secubox-crowdsec**: Behavioral threat detection complementing Wazuh
- **secubox-dpi**: Network DPI feed for alert enrichment
- **secubox-auth**: JWT authentication middleware

---

## References

- [Wazuh Official Documentation](https://documentation.wazuh.com)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [OSSEC Project](https://www.ossec.net)
- [SecuBox Security Platform](https://secubox.in)

---

## Author

**Gerald KERMA** (Gandalf)
CyberMind — Notre-Dame-du-Cruet, Savoie
https://cybermind.fr

---

## License

Proprietary | ANSSI CSPN Candidate
SecuBox Wazuh Integration Module — All Rights Reserved

---

## Changelog

### v1.0.0 (2025-04-08)
- Initial Debian port from OpenWrt secubox-openwrt
- FastAPI REST interface for Wazuh agent/manager
- Real-time alert monitoring and statistics
- File integrity monitoring (syscheck)
- Rootkit detection (rootcheck)
- Agent registration and management
- Manager control operations
