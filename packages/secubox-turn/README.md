# SecuBox TURN

TURN/STUN server management module for WebRTC using coturn. Provides NAT traversal services for peer-to-peer communication in WebRTC applications.

## Features

- TURN/STUN server management via coturn daemon
- Temporary credential generation with HMAC-SHA1 authentication
- User management (add/delete/list)
- Real-time session monitoring
- Connection statistics from logs
- Configuration management with backup
- Realm and secret management
- TLS support on port 5349
- Three-fold architecture endpoints (components, access)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check (public) |
| GET | /status | TURN server status and configuration summary |
| GET | /stats | Connection statistics (sessions, allocations, auth failures) |
| GET | /sessions | List active sessions with client IPs |
| POST | /start | Start coturn service |
| POST | /stop | Stop coturn service |
| POST | /restart | Restart coturn service |
| GET | /config | Get turnserver.conf content and parsed values |
| POST | /config | Update turnserver.conf configuration |
| GET | /users | List TURN users |
| POST | /users | Add a TURN user |
| DELETE | /users/{username} | Delete a TURN user |
| GET | /realm | Get realm and secret status |
| POST | /realm | Set realm and optionally regenerate secret |
| GET | /credentials | Generate temporary TURN credentials (test) |
| POST | /credentials | Generate credentials with custom username/TTL |
| POST | /generate_secret | Generate a new random auth secret |
| GET | /logs | Get TURN server logs |
| GET | /components | List TURN components (three-fold architecture) |
| GET | /access | Get access endpoints (STUN/TURN URLs) |

## Configuration

**Config file:** `/etc/turnserver.conf`

**Example configuration:**
```ini
# Network settings
listening-port=3478
tls-listening-port=5349
listening-ip=0.0.0.0

# Relay settings
relay-ip=AUTO_DETECT
min-port=49152
max-port=65535

# Authentication
lt-cred-mech
use-auth-secret
static-auth-secret=your-secret-here

# Realm
realm=turn.secubox.local

# Logging
log-file=/var/log/turnserver/turnserver.log
verbose

# Security
no-multicast-peers
no-cli
fingerprint
```

## Dependencies

- coturn
- python3-fastapi
- python3-pydantic
- secubox-core

## Files

- `/etc/turnserver.conf` - Main coturn configuration file
- `/var/lib/secubox/turn/users.json` - TURN users database
- `/var/lib/secubox/turn/config_cache.json` - Configuration cache
- `/var/log/turnserver/turnserver.log` - TURN server logs
- `/usr/bin/turnadmin` - User management CLI
- `/run/secubox/turn.sock` - Unix socket for FastAPI

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 3478 | UDP/TCP | STUN/TURN standard port |
| 5349 | TCP | TURNS (TLS) port |
| 49152-65535 | UDP | Relay port range |

## WebRTC Integration

Generate temporary credentials for WebRTC clients:

```javascript
// Example ICE server configuration
const iceServers = [
  {
    urls: ["stun:turn.secubox.local:3478"],
  },
  {
    urls: [
      "turn:turn.secubox.local:3478",
      "turn:turn.secubox.local:3478?transport=tcp",
      "turns:turn.secubox.local:5349"
    ],
    username: "timestamp:username",
    credential: "hmac-password"
  }
];
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
