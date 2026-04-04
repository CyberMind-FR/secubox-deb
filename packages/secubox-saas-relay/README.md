# secubox-saas-relay

**SecuBox SaaS/API Proxy Relay Module** - Phase 9

Secure proxy relay for external SaaS APIs with encrypted key storage, rate limiting, and health monitoring.

## Features

- **Proxy Configuration**: Configure and manage connections to external SaaS APIs
- **Encrypted Key Storage**: API keys are encrypted at rest using Fernet (symmetric encryption)
- **Rate Limiting**: Per-service rate limiting (requests per minute)
- **Quota Tracking**: Daily request quotas per service
- **Health Checks**: Background health monitoring with configurable endpoints
- **Request Logging**: Full request/response logging for audit and debugging
- **P31 Phosphor Dashboard**: Light theme web interface

## Installation

```bash
cd packages/secubox-saas-relay
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../secubox-saas-relay_1.0.0-1~bookworm1_all.deb
```

## API Endpoints

### Public Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/status` | GET | Module status |
| `/components` | GET | System components |
| `/access` | GET | Access points |

### Authenticated Endpoints (require JWT)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/services` | GET | List all services |
| `/service/{name}` | GET | Get service details |
| `/service/add` | POST | Add new service |
| `/service/{name}` | PUT | Update service |
| `/service/{name}` | DELETE | Remove service |
| `/service/{name}/toggle` | POST | Enable/disable service |
| `/service/{name}/check` | POST | Trigger health check |
| `/keys` | GET | List API keys (masked) |
| `/keys/{name}` | PUT | Update API key |
| `/keys/{name}` | DELETE | Delete API key |
| `/stats` | GET | Get all statistics |
| `/stats/{name}` | GET | Get service statistics |
| `/stats/reset/{name}` | POST | Reset service stats |
| `/logs` | GET | Get request logs |
| `/logs` | DELETE | Clear logs |
| `/health/all` | GET | All services health |
| `/proxy/{service}/{path}` | * | Proxy request to service |

## Configuration

Services are stored in `/var/lib/secubox/saas-relay/services.json`.
Encrypted API keys are stored in `/var/lib/secubox/saas-relay/keys.enc`.
Encryption key is stored in `/etc/secubox/secrets/saas-relay.key`.

### Service Configuration

```json
{
  "name": "my-api",
  "display_name": "My API Service",
  "base_url": "https://api.example.com",
  "service_type": "rest",
  "auth_header": "Authorization",
  "auth_prefix": "Bearer ",
  "health_endpoint": "/health",
  "rate_limit": 100,
  "quota_daily": 10000,
  "timeout": 30,
  "enabled": true
}
```

## Security

- API keys are encrypted using Fernet symmetric encryption
- Encryption key is stored with mode 0600 (owner read/write only)
- Keys file is stored with mode 0600
- All management endpoints require JWT authentication
- Rate limiting prevents abuse of proxied APIs
- Daily quotas prevent runaway costs

## Dashboard

Access the web dashboard at `/saas-relay/` after installation.

Features:
- Service list with health indicators
- API key management panel (masked display)
- Usage statistics with quota progress bars
- Request logs with filtering
- Add/remove service forms

## Systemd Service

```bash
# Start/stop service
sudo systemctl start secubox-saas-relay
sudo systemctl stop secubox-saas-relay

# View logs
sudo journalctl -u secubox-saas-relay -f
```

## Files

| Path | Description |
|------|-------------|
| `/usr/lib/secubox/saas-relay/` | API application |
| `/usr/share/secubox/www/saas-relay/` | Web dashboard |
| `/etc/nginx/secubox.d/saas-relay.conf` | Nginx config |
| `/var/lib/secubox/saas-relay/` | Data storage |
| `/etc/secubox/secrets/saas-relay.key` | Encryption key |
| `/run/secubox/saas-relay.sock` | Unix socket |

## Dependencies

- secubox-core (>= 1.0)
- python3-uvicorn
- python3-httpx
- python3-cryptography

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
