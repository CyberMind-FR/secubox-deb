# secubox-routes

SecuBox module for routing table viewing and management.

## Features

- View IPv4 and IPv6 routing tables
- Add and delete routes dynamically
- Policy routing rules management (`ip rule`)
- ARP (IPv4) and NDP (IPv6) neighbor table viewing
- Route cache flush capability
- P31 Phosphor light theme UI

## API Endpoints

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

### Status & Health

- `GET /api/v1/routes/status` - Module status with route/rule/neighbor counts
- `GET /api/v1/routes/health` - Health check (public endpoint)

### Routes

- `GET /api/v1/routes/routes` - All routes (IPv4 + IPv6)
- `GET /api/v1/routes/routes/ipv4` - IPv4 routes only
- `GET /api/v1/routes/routes/ipv6` - IPv6 routes only
- `POST /api/v1/routes/routes` - Add a route
- `DELETE /api/v1/routes/routes` - Delete a route

### Policy Rules

- `GET /api/v1/routes/rules` - List all policy routing rules
- `POST /api/v1/routes/rules` - Add a policy rule
- `DELETE /api/v1/routes/rules/{priority}` - Delete a rule by priority

### Tables & Neighbors

- `GET /api/v1/routes/tables` - List routing tables
- `GET /api/v1/routes/neighbors` - ARP/NDP neighbor table
- `POST /api/v1/routes/flush` - Flush route cache

## Request Examples

### Add Route
```json
POST /api/v1/routes/routes
{
  "destination": "10.0.0.0/8",
  "gateway": "192.168.1.1",
  "interface": "eth0",
  "metric": 100
}
```

### Add Policy Rule
```json
POST /api/v1/routes/rules
{
  "priority": 100,
  "from": "192.168.1.0/24",
  "table": "custom"
}
```

### Delete Route
```json
DELETE /api/v1/routes/routes
{
  "destination": "10.0.0.0/8",
  "gateway": "192.168.1.1"
}
```

## Dependencies

- `secubox-core` - Core library (JWT auth, logging, config)
- `iproute2` - Linux networking utilities (`ip` command)

## Files

```
/usr/lib/secubox/routes/api/         - FastAPI backend
/usr/share/secubox/www/routes/       - Frontend UI
/etc/nginx/secubox.d/routes.conf     - Nginx proxy config
/usr/share/secubox/menu.d/907-routes.json - Menu entry
/run/secubox/routes.sock             - Unix socket (runtime)
```

## Service

```bash
# Start/stop
systemctl start secubox-routes
systemctl stop secubox-routes

# View logs
journalctl -u secubox-routes -f
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
