# SecuBox SimpleX

Privacy-focused SimpleX Chat SMP/XFTP server module for SecuBox-DEB.

## Overview

SimpleX Chat is a decentralized messaging protocol that provides strong privacy guarantees:
- **No user identifiers**: Unlike other messaging apps, SimpleX does not assign user IDs
- **Zero-knowledge**: Server operators cannot see message content or metadata
- **Decentralized**: Users can run their own servers or use multiple servers
- **End-to-end encrypted**: All messages are encrypted client-side

This module manages a SimpleX SMP (Simple Messaging Protocol) relay server using Docker or Podman containers.

## Features

- SimpleX Chat SMP relay server deployment
- Docker/Podman container management
- TLS certificate generation and management
- Backup and restore functionality
- Connection and queue statistics
- Server configuration via web UI
- Real-time logs viewer

## Requirements

- Docker or Podman (container runtime)
- secubox-core
- nginx

## Installation

```bash
apt install secubox-simplex
```

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Server status

### Server Management
- `GET /server/info` - Detailed server information
- `GET /server/config` - Get configuration
- `POST /server/config` - Update configuration

### Statistics
- `GET /stats` - Overall statistics
- `GET /stats/queues` - Queue statistics
- `GET /stats/connections` - Active connections

### Container Management
- `GET /container/status` - Container status
- `POST /container/install` - Install server
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container
- `DELETE /container` - Remove container

### TLS Management
- `GET /tls/status` - TLS certificate status
- `POST /tls/renew` - Generate/renew certificate

### Backup & Restore
- `GET /backup` - List backups
- `POST /backup/create` - Create backup
- `POST /backup/restore` - Restore from backup
- `DELETE /backup/{name}` - Delete backup

### Utilities
- `GET /connection-string` - Get client connection string
- `GET /fingerprint` - Get server fingerprint
- `GET /logs` - View server logs
- `POST /maintenance/cleanup` - Clean old queues

## Web Interface

Access the web UI at: `https://your-secubox/simplex/`

Features:
- **Status Tab**: Server info, connection string for clients
- **Statistics Tab**: Queue and connection monitoring
- **Configuration Tab**: Server settings
- **TLS Tab**: Certificate management
- **Backup Tab**: Create and restore backups
- **Logs Tab**: Real-time log viewer

## Usage

### Initial Setup

1. Navigate to the SimpleX page in SecuBox dashboard
2. Enter your server's public address (or leave empty for auto-detect)
3. Click "Install SMP Server"
4. Wait for container deployment
5. Copy the connection string and add to SimpleX Chat app

### Adding to SimpleX Chat App

1. Open SimpleX Chat app
2. Go to Settings -> Network & Servers -> SMP Servers
3. Tap "Add Server"
4. Paste your server's connection string
5. Verify the server fingerprint

### Configuration

```json
{
  "server_address": "your-domain.com",
  "enable_xftp": false,
  "log_level": "info",
  "max_connections": 10000,
  "require_auth": false
}
```

## Files

- `/usr/lib/secubox/simplex/api/main.py` - API backend
- `/usr/share/secubox/www/simplex/` - Web interface
- `/etc/secubox/simplex/` - Configuration
- `/etc/secubox/simplex/tls/` - TLS certificates
- `/var/lib/secubox/simplex/` - Data directory
- `/var/lib/secubox/simplex/backups/` - Backup storage

## Security Considerations

- The SMP server runs in an isolated container
- TLS certificates are stored with restricted permissions (600)
- Server runs as root to manage Docker/Podman (required for container operations)
- All client-server communication is encrypted
- No user data or message content is stored on the server

## Ports

- **5223**: SMP protocol (SimpleX Messaging Protocol)
- **443**: XFTP protocol (optional, for file transfers)

## Troubleshooting

### Container won't start
```bash
# Check Docker/Podman status
systemctl status docker
systemctl status podman

# Check container logs
docker logs simplex-smp
podman logs simplex-smp
```

### Connection issues
```bash
# Verify port is listening
ss -tlnp | grep 5223

# Check firewall
nft list ruleset | grep 5223
```

### Reset installation
```bash
# Stop and remove container
docker rm -f simplex-smp

# Clear data (warning: removes all server data)
rm -rf /var/lib/secubox/simplex/smp/*

# Reinstall via web UI
```

## License

Proprietary - CyberMind / ANSSI CSPN candidate

## Author

Gerald Kerma <gandalf@gk2.net>
CyberMind - https://cybermind.fr
