# SecuBox Interceptor

Traffic interception and analysis module for SecuBox.

## Features

- **Traffic Interception**: HTTP/HTTPS traffic capture and analysis
- **SSL/TLS Inspection**: Decrypt and inspect encrypted traffic using CA certificate
- **Request/Response Modification**: Rule-based traffic modification
- **Traffic Recording**: Record sessions for later analysis and replay
- **Protocol Analysis**: Deep inspection of HTTP protocols
- **Content Filtering**: Block malware, scripts, and trackers
- **Session Management**: Track and manage active connections
- **WAF Integration**: Seamless integration with SecuBox WAF module

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status and statistics

### Configuration
- `GET /config` - Get current configuration
- `POST /config` - Update configuration

### Sessions
- `GET /sessions` - List active sessions
- `GET /session/{id}` - Get session details
- `POST /session/{id}/close` - Close a session

### Flows
- `GET /flows` - List intercepted flows
- `GET /flow/{id}` - Get flow details
- `POST /flow/{id}/replay` - Replay a captured flow

### Rules
- `GET /rules` - List interception rules
- `POST /rule` - Create a new rule
- `PUT /rule/{id}` - Update a rule
- `DELETE /rule/{id}` - Delete a rule

### Recordings
- `GET /recordings` - List recorded sessions
- `POST /record/start` - Start traffic recording
- `POST /record/stop` - Stop traffic recording

### Statistics & Logs
- `GET /stats` - Traffic statistics
- `GET /logs` - Interceptor logs

### Service Control
- `POST /start` - Start interceptor
- `POST /stop` - Stop interceptor
- `POST /restart` - Restart interceptor

## Configuration

Configuration is stored in `/etc/secubox/interceptor.json`:

```json
{
  "enabled": true,
  "listen_port": 8889,
  "ssl_inspection": true,
  "ca_cert": "/etc/secubox/interceptor/ca.crt",
  "ca_key": "/etc/secubox/interceptor/ca.key",
  "recording_enabled": false,
  "waf_integration": true,
  "content_filters": {
    "block_malware": true,
    "block_scripts": false,
    "block_trackers": false
  }
}
```

## CA Certificate

A self-signed CA certificate is generated during installation at:
- Certificate: `/etc/secubox/interceptor/ca.crt`
- Private Key: `/etc/secubox/interceptor/ca.key`

For SSL/TLS inspection to work, clients must trust this CA certificate.

## Rule Format

Rules are defined in JSON format with conditions and actions:

```json
{
  "name": "Block Tracking Scripts",
  "description": "Block known tracking domains",
  "enabled": true,
  "match_type": "request",
  "conditions": [
    {"field": "host", "operator": "contains", "value": "analytics.google.com"}
  ],
  "actions": [
    {"type": "block"}
  ]
}
```

### Condition Operators
- `equals`, `contains`, `starts_with`, `ends_with`
- `matches` (regex)
- `in` (list membership)

### Action Types
- `block` - Block the request
- `modify_header` - Modify request/response headers
- `modify_body` - Modify request/response body
- `log` - Log the flow
- `tag` - Tag for later analysis

## Files

- `/usr/lib/secubox/interceptor/` - API code
- `/usr/share/secubox/www/interceptor/` - Web frontend
- `/etc/secubox/interceptor.json` - Configuration
- `/etc/secubox/interceptor/` - CA certificates
- `/var/lib/secubox/interceptor/` - Data storage
- `/var/log/secubox/interceptor.log` - Logs

## Service Management

```bash
# Start/stop/restart
systemctl start secubox-interceptor
systemctl stop secubox-interceptor
systemctl restart secubox-interceptor

# Check status
systemctl status secubox-interceptor

# View logs
journalctl -u secubox-interceptor -f
```

## Web Interface

Access the dashboard at: `https://<secubox-ip>/interceptor/`

Features:
- Sessions tab: View and manage active sessions
- Flows tab: Browse intercepted traffic with request/response viewer
- Rules tab: Create and manage interception rules
- Recordings tab: Start/stop recording and view recordings
- Statistics tab: Traffic analysis charts and metrics
- Settings tab: Configure SSL inspection and content filters

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
