# secubox-peertube

SecuBox module for PeerTube federated video platform management.

## Overview

This module provides Docker/Podman container management for PeerTube, a decentralized video hosting platform compatible with ActivityPub federation.

## Features

- **Container Management**: Install, start, stop, restart PeerTube container
- **Video Management**: List and delete videos
- **Channel Management**: Create, list, delete video channels
- **User Management**: Create, list, delete users with roles (admin/moderator/user)
- **Federation (ActivityPub)**: Follow/unfollow instances, view followers
- **Transcoding**: Configure HLS, WebTorrent, resolutions, thread count
- **Plugins**: Install/uninstall plugins from NPM registry
- **Storage**: Monitor disk usage by category (videos, thumbnails, HLS, etc.)
- **Logs**: View container logs

## API Endpoints

### Public
- `GET /health` - Health check
- `GET /status` - Service status and statistics

### Instance
- `GET /instance` - Get instance information
- `POST /instance` - Update instance settings

### Videos
- `GET /videos` - List videos
- `DELETE /video/{id}` - Delete a video

### Channels
- `GET /channels` - List channels
- `POST /channel` - Create channel
- `DELETE /channel/{name}` - Delete channel

### Users
- `GET /users` - List users
- `POST /user` - Create user
- `DELETE /user/{id}` - Delete user

### Federation
- `GET /federation/followers` - List followers
- `GET /federation/following` - List following
- `POST /federation/follow` - Follow instance(s)
- `DELETE /federation/following/{id}` - Unfollow instance

### Transcoding
- `GET /transcoding/jobs` - List transcoding jobs
- `GET /transcoding/settings` - Get settings
- `POST /transcoding/settings` - Update settings

### Storage
- `GET /storage/stats` - Get storage statistics

### Plugins
- `GET /plugins` - List installed plugins
- `POST /plugin/install` - Install plugin
- `DELETE /plugin/{name}` - Uninstall plugin

### Container
- `GET /container/status` - Container status
- `POST /container/install` - Pull image
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container
- `POST /container/uninstall` - Remove container (data preserved)

### Logs
- `GET /logs` - Container logs

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

## Configuration

Configuration is stored in `/etc/secubox/peertube.toml`:

```toml
enabled = true
image = "chocobozzz/peertube:production-bookworm"
http_port = 9000
data_path = "/srv/peertube"
timezone = "Europe/Paris"
domain = "peertube.secubox.local"
transcoding_enabled = true
transcoding_threads = 2
hls_enabled = true
webtorrent_enabled = true
federation_enabled = true
```

## Data Storage

PeerTube data is stored in `/srv/peertube/`:
- `storage/` - Videos, thumbnails, HLS playlists
- `config/` - PeerTube configuration
- `data/` - Database and cache

## Dependencies

- Docker or Podman
- secubox-core
- python3-uvicorn

## Theme

Uses P31 Phosphor light theme with PeerTube orange accent (`#f1680d`).

## License

Proprietary - CyberMind / ANSSI CSPN candidate
