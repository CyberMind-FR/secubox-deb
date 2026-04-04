# secubox-torrent

BitTorrent client management module for SecuBox-DEB.

## Features

- **Transmission Docker Container**: Managed BitTorrent client via Docker/Podman
- **Torrent Lifecycle**: Add, remove, pause, resume torrents
- **Multiple Input Methods**: Magnet links, URLs, or .torrent file uploads
- **Speed Limiting**: Configurable download/upload limits with alternative "turtle mode"
- **RSS Feeds**: Subscribe to RSS feeds for automatic torrent downloads
- **Categories**: Organize torrents with categories and custom save paths
- **Statistics**: Real-time download/upload speeds and transfer totals
- **P31 Phosphor Theme**: Light CRT-style web interface with green (#22c55e) accent

## API Endpoints

### Public
- `GET /health` - Health check
- `GET /status` - Service status

### Torrents (JWT required)
- `GET /torrents` - List all torrents
- `POST /torrent/add` - Add torrent (magnet/URL/file)
- `DELETE /torrent/{id}` - Remove torrent
- `POST /torrent/{id}/pause` - Pause torrent
- `POST /torrent/{id}/resume` - Resume torrent
- `GET /torrent/{id}/files` - List files in torrent

### Statistics
- `GET /stats` - Download/upload statistics

### RSS Feeds
- `GET /rss/feeds` - List RSS subscriptions
- `POST /rss/add` - Add RSS feed
- `DELETE /rss/{feed_id}` - Remove RSS feed

### Categories
- `GET /categories` - List categories
- `POST /categories` - Add category
- `DELETE /categories/{id}` - Remove category

### Configuration
- `GET /config` - Get settings
- `POST /config` - Update settings

### Container Management
- `GET /container/status` - Docker/Podman status
- `POST /container/install` - Pull Transmission image
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container
- `POST /container/uninstall` - Remove container

### Logs
- `GET /logs` - Container logs

## Configuration

Configuration stored in `/etc/secubox/torrent.toml`:

```toml
enabled = false
client = "transmission"
image = "linuxserver/transmission:latest"
port = 9091
peer_port = 51413
data_path = "/srv/torrent"
download_dir = "/srv/torrent/downloads"
watch_dir = "/srv/torrent/watch"
timezone = "Europe/Paris"
download_limit = 0
upload_limit = 0
seed_ratio_limit = 2.0
```

## Directory Structure

```
/srv/torrent/
├── config/      # Transmission configuration
├── downloads/   # Downloaded files
└── watch/       # Watch directory for .torrent files
```

## Ports

- **9091**: Transmission Web UI (localhost only)
- **51413**: BitTorrent peer port (TCP/UDP)

## Dependencies

- `secubox-core` - Core library
- `docker.io` or `podman` - Container runtime
- `python3-uvicorn` - ASGI server

## License

Proprietary - CyberMind / ANSSI CSPN candidate

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
