# SecuBox Metacatalog

Service catalog and registry module for SecuBox-DEB.

## Overview

The metacatalog module provides a centralized view of all installed SecuBox services, including:

- Service health status tracking
- Dependency mapping between services
- API endpoint documentation
- Service metadata (version, ports, sockets)

## API Endpoints

All endpoints require JWT authentication except `/health`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/metacatalog/health` | Health check (public) |
| GET | `/api/v1/metacatalog/status` | Module status with stats |
| GET | `/api/v1/metacatalog/services` | List all services |
| GET | `/api/v1/metacatalog/service/{name}` | Get service details |
| GET | `/api/v1/metacatalog/dependencies` | Get full dependency graph |
| GET | `/api/v1/metacatalog/dependencies/{name}` | Get service dependencies |
| GET | `/api/v1/metacatalog/endpoints` | Get all API endpoints |
| GET | `/api/v1/metacatalog/endpoints/{name}` | Get service endpoints |
| GET | `/api/v1/metacatalog/categories` | List service categories |
| POST | `/api/v1/metacatalog/refresh` | Force catalog refresh |

## Query Parameters

The `/services` endpoint supports filtering:

- `category`: Filter by category (system, security, network, monitoring)
- `status`: Filter by status (running, stopped, failed, unknown)
- `installed_only`: Boolean to show only installed services

## Frontend

The P31 Phosphor light theme frontend is available at `/metacatalog/`.

Features:
- Service grid with health indicators
- Interactive dependency graph visualization
- API endpoint documentation viewer
- Search and filter functionality

## Service Discovery

The module discovers services by:

1. Scanning for known SecuBox service patterns
2. Querying systemd for service status
3. Reading menu.d entries for UI metadata
4. Optionally fetching OpenAPI specs from running services

## Configuration

The module uses the standard SecuBox configuration:

- Socket: `/run/secubox/metacatalog.sock`
- Cache: `/var/cache/secubox/metacatalog/catalog.json`
- Systemd unit: `secubox-metacatalog.service`

## Dependencies

- secubox-core (>= 1.0)
- python3-fastapi
- python3-uvicorn

## Installation

```bash
apt install secubox-metacatalog
```

## Building

```bash
cd packages/secubox-metacatalog
dpkg-buildpackage -us -uc -b
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
