# SecuBox RTTY

Web-based remote terminal access module for SecuBox. Provides secure browser-accessible shell sessions through the rtty daemon with token-based authentication.

## Features

- Service management (start/stop/restart rtty daemon)
- Active terminal session monitoring
- Secure access token generation with configurable TTL
- Token lifecycle management (create/list/revoke)
- SSL/TLS configuration support
- Configuration management with backup
- Service log viewing (file and journalctl)
- Three-fold architecture endpoints (Components/Status/Access)
- WebSocket-based terminal communication

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check (public) |
| GET | /status | Service status, ports, sessions count |
| GET | /sessions | List active terminal sessions |
| POST | /start | Start rtty service |
| POST | /stop | Stop rtty service |
| POST | /restart | Restart rtty service |
| GET | /config | Get rtty configuration |
| POST | /config | Update rtty configuration |
| GET | /logs | Get service logs |
| POST | /token | Generate access token |
| GET | /tokens | List access tokens (metadata only) |
| DELETE | /tokens/{name} | Revoke access token |
| GET | /components | Three-fold: list components |
| GET | /access | Three-fold: get access endpoints |

## Configuration

**Main config file:** `/etc/rtty/rtty.conf`

Example configuration:
```ini
# Server settings
host = "0.0.0.0"
port = 5912
http_port = 5913

# SSL/TLS
ssl = false
ssl_cert = "/etc/ssl/certs/rtty.crt"
ssl_key = "/etc/ssl/private/rtty.key"

# Authentication
token = "your-secure-token"

# Interface
web_root = "/usr/share/rtty/www"

# Logging
log_level = "info"
```

### Config Update (POST /config)

```json
{
  "host": "0.0.0.0",
  "port": 5912,
  "http_port": 5913,
  "ssl": false,
  "ssl_cert": "/etc/ssl/certs/rtty.crt",
  "ssl_key": "/etc/ssl/private/rtty.key",
  "token": "new-token",
  "log_level": "info"
}
```

### Token Generation (POST /token)

```json
{
  "name": "admin-session",
  "ttl": 86400
}
```

Response includes an `access_url` for direct terminal access.

## Dependencies

- secubox-core
- rtty (rtty daemon)

## Files

- `/etc/rtty/rtty.conf` - Main configuration file
- `/var/lib/secubox/rtty/tokens.json` - Access tokens database
- `/var/lib/secubox/rtty/config_cache.json` - Configuration cache
- `/var/log/rtty/rtty.log` - Service log file
- `/run/secubox/rtty.sock` - Unix socket for API

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 5912 | TCP | rtty API port |
| 5913 | TCP | Web terminal HTTP/WebSocket port |

## Usage Examples

### Generate terminal access token

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"name": "support-session", "ttl": 3600}' \
     http://localhost/api/v1/rtty/token
```

### Check active sessions

```bash
curl -H "Authorization: Bearer $JWT" \
     http://localhost/api/v1/rtty/sessions
```

### Enable SSL

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"ssl": true, "ssl_cert": "/etc/ssl/certs/rtty.crt", "ssl_key": "/etc/ssl/private/rtty.key"}' \
     http://localhost/api/v1/rtty/config

curl -X POST -H "Authorization: Bearer $JWT" \
     http://localhost/api/v1/rtty/restart
```

## Security Notes

- All API endpoints (except /health) require JWT authentication
- Access tokens are stored with expiration timestamps
- Actual token values are never exposed in list operations
- Configuration backup is created before updates
- SSL/TLS is recommended for production deployments

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
