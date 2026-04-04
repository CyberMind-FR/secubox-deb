# SecuBox Jitsi Meet

Video conferencing module for SecuBox-DEB.

## Overview

SecuBox Jitsi provides a complete, self-hosted video conferencing solution using Docker containers. It includes the full Jitsi Meet stack with optional recording capabilities via Jibri.

## Features

- **Full Jitsi Stack**: Web, Prosody (XMPP), Jicofo, JVB (Videobridge)
- **Authentication**: Internal (Prosody), JWT tokens, or LDAP
- **Recording**: Jibri for session recording and live streaming
- **Security**: SRTP/SRTCP encryption, secure RTP
- **Lobby & Breakout Rooms**: Meeting moderation features
- **Docker-based**: Easy deployment with docker-compose

## Architecture

```
                     +------------------+
                     |   SecuBox Hub    |
                     +--------+---------+
                              |
                     +--------v---------+
                     | secubox-jitsi    |
                     | FastAPI Backend  |
                     +--------+---------+
                              |
              +---------------+---------------+
              |               |               |
       +------v------+ +------v------+ +------v------+
       | jitsi-web   | | prosody     | | jicofo      |
       | (nginx)     | | (XMPP)      | | (focus)     |
       +-------------+ +-------------+ +------+------+
                                              |
                              +---------------+---------------+
                              |                               |
                       +------v------+                 +------v------+
                       | jvb         |                 | jibri       |
                       | (videobridge)|                | (recording) |
                       +-------------+                 +-------------+
```

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Comprehensive status with container info

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

### Room Management
- `GET /rooms` - List active rooms/conferences
- `GET /room/{name}` - Get room details
- `POST /room/{name}/close` - Close room (requires Prosody mod)

### Statistics
- `GET /stats` - Detailed JVB statistics

### Recordings
- `GET /recordings` - List recordings
- `DELETE /recording/{id}` - Delete recording

### Authentication
- `GET /auth/config` - Get auth configuration
- `POST /auth/config` - Update auth (JWT secret, LDAP, etc.)

### Prosody XMPP
- `GET /prosody/status` - XMPP server status

### Jibri Recording
- `GET /jibri/status` - Recording service status
- `POST /jibri/enable` - Enable Jibri
- `POST /jibri/disable` - Disable Jibri

### Container Management
- `GET /container/status` - Container status
- `POST /container/install` - Install Jitsi stack
- `POST /container/start` - Start containers
- `POST /container/stop` - Stop containers
- `POST /container/restart` - Restart containers
- `POST /container/uninstall` - Remove containers

### Logs
- `GET /logs?service=web&lines=100` - Container logs

## Configuration

Configuration stored in `/etc/secubox/jitsi.toml`:

```toml
enabled = true
domain = "meet.secubox.local"
public_url = "https://meet.secubox.local"
timezone = "Europe/Paris"
http_port = 8443
https_port = 443
jvb_port = 10000
auth_enabled = false
auth_type = "internal"
jwt_secret = ""
jwt_app_id = "secubox"
enable_lobby = true
enable_breakout_rooms = true
enable_recording = false
jibri_enabled = false
max_participants = 100
welcome_message = "Welcome to SecuBox Meeting"
```

## Data Directories

- `/srv/jitsi/` - Jitsi data and configuration
- `/srv/jitsi/recordings/` - Recorded meetings
- `/srv/jitsi/web/` - Web container config
- `/srv/jitsi/prosody/` - XMPP server config
- `/srv/jitsi/jicofo/` - Jicofo config
- `/srv/jitsi/jvb/` - Videobridge config
- `/srv/jitsi/jibri/` - Recording service config

## Ports

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| 8443 | TCP | HTTP | Web interface (internal) |
| 443 | TCP | HTTPS | Web interface (internal) |
| 10000 | UDP | JVB | Video/audio RTP |
| 5222 | TCP | XMPP | Prosody client connections |
| 5347 | TCP | XMPP | Prosody component connections |

## Quick Start

1. Install the package:
   ```bash
   apt install secubox-jitsi
   ```

2. Access the dashboard at `/jitsi/`

3. Click "Install Jitsi Meet" to download and configure containers

4. Start the service and join a meeting

## Authentication Types

### Internal (Prosody)
Users registered in Prosody's internal database.

### JWT
Token-based authentication for integration with external systems:
- Set `jwt_app_id` and `jwt_secret`
- Generate tokens with matching credentials

### LDAP
Enterprise directory integration:
- Set `ldap_url` and `ldap_base`
- Users authenticate against LDAP server

## Recording with Jibri

Jibri provides recording and live streaming:

1. Enable Jibri from the Recordings tab
2. Restart Jitsi to apply
3. Start recording from within meetings
4. Recordings saved to `/srv/jitsi/recordings/`

**Note**: Jibri requires significant resources (2GB+ RAM, privileged container).

## Firewall Rules

Ensure these ports are open for external participants:

```bash
# nftables example
nft add rule inet filter input udp dport 10000 accept
```

## Dependencies

- `secubox-core` - Core library
- `docker.io` or `podman` - Container runtime
- `docker-compose` or `podman-compose` - Orchestration
- `nginx` - Reverse proxy (recommended)

## License

Proprietary - CyberMind ANSSI CSPN Candidate

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
