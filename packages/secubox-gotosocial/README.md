# SecuBox GoToSocial

GoToSocial ActivityPub/Fediverse server module for SecuBox-DEB.

## Overview

GoToSocial is a lightweight, fast ActivityPub social network server. This module provides:

- Docker/Podman container management
- User account management (create, suspend, promote, demote)
- Federation controls (domain blocking/allowing)
- Media storage management and cleanup
- Custom emoji management
- Moderation tools
- Web dashboard with P31 Phosphor light theme

## Installation

```bash
apt install secubox-gotosocial
```

Requires Docker or Podman to be installed.

## Configuration

Configuration stored in `/etc/secubox/gotosocial.toml`:

```toml
enabled = true
image = "superseriousbusiness/gotosocial:latest"
port = 8080
data_path = "/srv/gotosocial"
domain = "social.example.com"
registration_open = false
approval_required = true
```

## API Endpoints

All endpoints require JWT authentication except `/health` and `/status`.

### Health & Status
- `GET /api/v1/gotosocial/health` - Health check
- `GET /api/v1/gotosocial/status` - Service status

### Instance
- `GET /api/v1/gotosocial/instance` - Get instance info
- `POST /api/v1/gotosocial/instance` - Update instance settings

### Accounts
- `GET /api/v1/gotosocial/accounts` - List accounts
- `POST /api/v1/gotosocial/account` - Create account
- `DELETE /api/v1/gotosocial/account/{username}` - Delete account
- `POST /api/v1/gotosocial/account/{username}/suspend` - Suspend account
- `POST /api/v1/gotosocial/account/{username}/unsuspend` - Unsuspend
- `POST /api/v1/gotosocial/account/{username}/promote` - Promote to admin
- `POST /api/v1/gotosocial/account/{username}/demote` - Demote from admin

### Federation
- `GET /api/v1/gotosocial/federation/peers` - List blocked/allowed domains
- `POST /api/v1/gotosocial/federation/block` - Block domain
- `DELETE /api/v1/gotosocial/federation/block/{domain}` - Unblock domain
- `POST /api/v1/gotosocial/federation/allow` - Allow domain
- `DELETE /api/v1/gotosocial/federation/allow/{domain}` - Remove from allowlist

### Media
- `GET /api/v1/gotosocial/media/stats` - Storage statistics
- `POST /api/v1/gotosocial/media/cleanup` - Clean remote cache
- `POST /api/v1/gotosocial/media/prune/orphaned` - Prune orphaned media

### Emojis
- `GET /api/v1/gotosocial/emojis` - List custom emojis
- `POST /api/v1/gotosocial/emoji` - Upload emoji
- `DELETE /api/v1/gotosocial/emoji/{shortcode}` - Delete emoji

### Container
- `GET /api/v1/gotosocial/container/status` - Container status
- `POST /api/v1/gotosocial/container/install` - Install (pull image)
- `POST /api/v1/gotosocial/container/start` - Start container
- `POST /api/v1/gotosocial/container/stop` - Stop container
- `POST /api/v1/gotosocial/container/restart` - Restart container
- `POST /api/v1/gotosocial/container/update` - Update to latest image
- `POST /api/v1/gotosocial/container/uninstall` - Remove container

### Logs
- `GET /api/v1/gotosocial/logs` - Get container logs

## Web Interface

Access the dashboard at `https://your-secubox/gotosocial/`

Features:
- Instance settings management
- Account table with suspend/promote actions
- Federation domain blocking/allowing
- Media storage dashboard
- Logs viewer

## Data Storage

Data is stored in `/srv/gotosocial/`:
- `sqlite.db` - SQLite database
- `storage/` - Media attachments, emojis, cache

## Backups

Create backup via API:
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-secubox/api/v1/gotosocial/backup
```

Backups are stored in `/var/lib/secubox/backups/gotosocial/`

## License

Proprietary - CyberMind / SecuBox
