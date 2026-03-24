# API Reference

[Francais](API-Reference-FR) | [中文](API-Reference-ZH)

All SecuBox modules expose REST APIs via Unix sockets, proxied by nginx at `/api/v1/<module>/`.

## Authentication

### Login

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Response:
```json
{
  "success": true,
  "token": "eyJ...",
  "username": "admin",
  "role": "admin"
}
```

### Using Token

```bash
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

## Common Endpoints

All modules implement:

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Module status |
| `/health` | GET | No | Health check |

## Hub API (`/api/v1/hub/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Full dashboard data |
| `/menu` | GET | Dynamic sidebar menu |
| `/modules` | GET | Module status list |
| `/alerts` | GET | Active alerts |
| `/roadmap` | GET | Migration progress |
| `/system_health` | GET | System health score |
| `/network_summary` | GET | Network status |

## CrowdSec API (`/api/v1/crowdsec/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | CrowdSec metrics |
| `/decisions` | GET | Active decisions |
| `/alerts` | GET | Security alerts |
| `/bouncers` | GET | Bouncer status |
| `/ban` | POST | Ban IP address |
| `/unban` | POST | Unban IP address |

### Ban IP

```bash
curl -X POST https://localhost/api/v1/crowdsec/ban \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.1.100","duration":"24h","reason":"manual"}'
```

## WireGuard API (`/api/v1/wireguard/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/interfaces` | GET | WG interfaces |
| `/peers` | GET | Peer list |
| `/peer` | POST | Add peer |
| `/peer/{id}` | DELETE | Remove peer |
| `/qrcode/{peer}` | GET | Peer QR code |

### Add Peer

```bash
curl -X POST https://localhost/api/v1/wireguard/peer \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"mobile","allowed_ips":"10.0.0.2/32"}'
```

## HAProxy API (`/api/v1/haproxy/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/stats` | GET | HAProxy statistics |
| `/backends` | GET | Backend servers |
| `/frontends` | GET | Frontend listeners |
| `/acls` | GET | Access control lists |

## DPI API (`/api/v1/dpi/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/flows` | GET | Active flows |
| `/applications` | GET | Detected apps |
| `/protocols` | GET | Protocol stats |
| `/top_hosts` | GET | Top talkers |

## QoS API (`/api/v1/qos/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | QoS status |
| `/classes` | GET | Traffic classes |
| `/rules` | GET | Shaping rules |
| `/stats` | GET | Bandwidth stats |

## System API (`/api/v1/system/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/info` | GET | System information |
| `/services` | GET | Service status |
| `/logs` | GET | System logs |
| `/reboot` | POST | Reboot system |
| `/update` | POST | Update packages |

## Error Responses

```json
{
  "success": false,
  "error": "Unauthorized",
  "code": 401
}
```

| Code | Description |
|------|-------------|
| 400 | Bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 500 | Server error |

## Rate Limiting

- 100 requests/minute per IP
- 1000 requests/minute authenticated

## WebSocket

Real-time updates available at `wss://localhost/api/v1/ws/`:

```javascript
const ws = new WebSocket('wss://localhost/api/v1/ws/');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```

## See Also

- [[Configuration]] - API configuration
- [[Modules]] - Module details
