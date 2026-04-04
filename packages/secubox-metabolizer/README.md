# SecuBox Metabolizer

Log processor and analyzer module for SecuBox-DEB.

## Overview

SecuBox Metabolizer parses journalctl logs, extracts patterns, calculates statistics, and monitors log rotation across all SecuBox services.

## Features

- **Pattern Detection**: Automatically identifies error patterns, warnings, authentication failures, connection issues, service state changes, and security events
- **Statistics**: Calculates lines per hour, error rates, and priority distribution
- **Service Aggregation**: Aggregates logs from multiple SecuBox services
- **Trend Analysis**: Hourly trend charts and error rate monitoring
- **Log Rotation**: Monitors log file rotation status and disk usage

## API Endpoints

All endpoints require JWT authentication via `Authorization: Bearer <token>`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (public) |
| `/status` | GET | Module status and overview |
| `/stats` | GET | Overall log statistics |
| `/analyze` | GET | Analyze logs and extract patterns |
| `/services` | GET | List available services |
| `/services/{name}/stats` | GET | Service-specific statistics |
| `/services/{name}/logs` | GET | Service raw logs |
| `/patterns` | GET | Detected patterns across services |
| `/errors` | GET | Recent errors and critical entries |
| `/rotation` | GET | Log file rotation information |

### Query Parameters

- `since`: Time window (e.g., "1h", "6h", "24h", "7d")
- `priority`: Filter by syslog priority (0-7)
- `service`: Filter by service name
- `limit`: Maximum entries to return
- `pattern_type`: Filter patterns by type

## Pattern Types

| Type | Description |
|------|-------------|
| `error` | Error/failure messages |
| `warning` | Warnings and deprecated notices |
| `auth_failure` | Authentication failures |
| `connection` | Connection issues |
| `service_state` | Service start/stop/restart |
| `security` | Security events (blocked, banned, etc.) |

## Installation

```bash
apt install secubox-metabolizer
```

## Dependencies

- secubox-core (>= 1.0)
- python3-fastapi
- python3-uvicorn

## Systemd Service

```bash
# Status
systemctl status secubox-metabolizer

# Logs
journalctl -u secubox-metabolizer -f

# Restart
systemctl restart secubox-metabolizer
```

## Configuration

The service runs on Unix socket `/run/secubox/metabolizer.sock` with nginx reverse proxy at `/api/v1/metabolizer/`.

Cache is stored at `/var/cache/secubox/metabolizer/stats.json` and refreshed every 60 seconds.

## Frontend

Web UI available at `/metabolizer/` with P31 Phosphor light theme featuring:

- Overview dashboard with hourly trends and priority distribution
- Pattern detection panel
- Error log viewer
- Service selector with per-service statistics
- Log file rotation status

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr

## License

Proprietary / ANSSI CSPN candidate
