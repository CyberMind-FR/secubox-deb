# SecuBox Matrix

Matrix Synapse homeserver management module for SecuBox-Deb.

## Overview

SecuBox Matrix provides a complete Matrix chat server infrastructure with:
- LXC container-based deployment for isolation
- Docker/Podman container support
- Full Synapse Admin API integration
- User and room management
- Federation control
- Media storage management
- Registration token system
- Element web client integration
- Bridge support (Telegram, Discord, Signal, etc.)

## Installation

```bash
apt install secubox-matrix
```

## API Endpoints

### Health and Status
- `GET /health` - Health check
- `GET /status` - Server status
- `GET /server/info` - Detailed server information

### Configuration
- `GET /config` - Get current configuration
- `POST /config` - Update configuration

### User Management
- `GET /users` - List users
- `POST /users` - Create user
- `DELETE /users/{username}` - Delete user
- `POST /users/{username}/reset-password` - Reset password
- `POST /user/{user_id}/deactivate` - Deactivate user

### Room Management
- `GET /rooms` - List rooms
- `GET /room/{room_id}` - Room details
- `DELETE /room/{room_id}` - Delete room

### Federation
- `GET /federation` - Federation status (LXC)
- `GET /federation/status` - Federation status
- `GET /federation/peers` - List federated servers
- `POST /federation/block` - Block a server

### Media
- `GET /media/stats` - Media storage statistics
- `POST /media/purge` - Purge old remote media cache

### Registration
- `GET /registrations` - Registration settings and tokens
- `POST /registrations/token` - Generate registration token
- `DELETE /registrations/token/{token}` - Delete token

### Container Management (Docker/Podman)
- `GET /container/status` - Container status
- `POST /container/install` - Install via container
- `POST /container/start` - Start containers
- `POST /container/stop` - Stop containers
- `POST /container/restart` - Restart containers

### LXC Lifecycle
- `POST /install` - Install in LXC container
- `POST /start` - Start LXC container
- `POST /stop` - Stop LXC container
- `POST /restart` - Restart Matrix service
- `DELETE /uninstall` - Remove container (keeps data)

### Utilities
- `GET /logs` - Get logs
- `POST /backup` - Create backup
- `GET /bridges` - List available bridges
- `POST /bridges/{id}/install` - Install bridge
- `POST /element/install` - Install Element web client

## Configuration

Configuration is stored in the Matrix homeserver.yaml within the container.
Key settings:
- `server_name` - Matrix server domain (cannot be changed after install)
- `enable_registration` - Allow public registration
- `registration_requires_token` - Require token for registration
- `allow_guest_access` - Allow guest accounts
- `max_upload_size` - Maximum file upload size

## Web Interface

Access the Matrix dashboard at `/matrix/` in the SecuBox web interface.

Features:
- Server status and configuration
- User management with password reset
- Room listing and deletion
- Federation peer monitoring
- Media storage dashboard
- Registration token generation
- Log viewer

## Ports

- 8008 - Client API
- 8448 - Federation (server-to-server)

## Data Storage

- LXC: `/var/lib/secubox/matrix/data/`
- Docker: `/opt/secubox/matrix/data/`
- Backups: `/var/lib/secubox/backups/matrix/`

## Author

Gerald Kerma / CyberMind
https://cybermind.fr
