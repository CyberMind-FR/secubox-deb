# secubox-mirror

Mirror/CDN Caching module for SecuBox-DEB.

## Overview

secubox-mirror provides local APT repository mirroring and content caching for SecuBox appliances. It uses nginx as a caching proxy to reduce bandwidth consumption and improve package download speeds.

## Features

- **APT Repository Mirroring**: Cache Debian/Ubuntu package repositories locally
- **Multi-Type Support**: APT, NPM, PyPI, Docker registries, or generic HTTP
- **Cache Statistics**: Monitor hit rates, disk usage, and bandwidth savings
- **Sync Management**: Manual or scheduled mirror synchronization
- **Cache Control**: Purge all cache or specific paths/domains

## API Endpoints

All endpoints require JWT authentication except `/health`.

### Status & Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/status` | Service status and stats |

### Mirror Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mirrors` | List all mirrors |
| GET | `/mirror/{name}` | Get mirror details |
| POST | `/mirror/add` | Add new mirror |
| POST | `/mirror/remove?name=X` | Remove mirror |
| POST | `/mirror/{name}/update` | Update mirror config |

### Cache Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cache/stats` | Cache statistics |
| GET | `/cache/list` | List cached files |
| POST | `/cache/purge` | Purge all cache |
| POST | `/cache/purge?path=X` | Purge specific path |
| POST | `/cache/purge_expired` | Purge expired entries |

### Sync Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/sync` | Sync all enabled mirrors |
| POST | `/sync/{name}` | Sync specific mirror |

### Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config` | Get global config |
| POST | `/config` | Update global config |

## Configuration

Configuration is stored in `/etc/secubox/mirror.json`:

```json
{
  "enabled": true,
  "cache_size": "10g",
  "cache_ttl": 86400,
  "mirrors": [
    {
      "id": "abc123",
      "name": "debian-bookworm",
      "url": "https://deb.debian.org/debian",
      "type": "apt",
      "enabled": true,
      "sync_interval": 3600,
      "max_size": "5g"
    }
  ]
}
```

## File Locations

| Path | Description |
|------|-------------|
| `/etc/secubox/mirror.json` | Main configuration |
| `/var/cache/secubox-mirror/` | Cache storage |
| `/var/lib/secubox/mirrors/` | Mirror metadata |
| `/var/lib/secubox/mirror-sync.json` | Sync state |
| `/etc/nginx/secubox-mirror.d/` | Per-mirror nginx configs |
| `/run/secubox/mirror.sock` | API Unix socket |

## Systemd Service

```bash
# Check status
systemctl status secubox-mirror

# Restart service
systemctl restart secubox-mirror

# View logs
journalctl -u secubox-mirror -f
```

## Building

```bash
cd packages/secubox-mirror
dpkg-buildpackage -us -uc -b
```

## Dependencies

- secubox-core (>= 1.0)
- nginx
- python3-fastapi
- python3-uvicorn
- curl

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
