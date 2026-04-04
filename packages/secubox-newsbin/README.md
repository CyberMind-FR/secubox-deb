# SecuBox Newsbin

Usenet downloader management module for SecuBox-DEB. Provides SABnzbd container management for NZB downloads.

## Features

- **SABnzbd Container Management**: Install, start, stop, restart, update Docker/Podman container
- **NZB Handling**: Add NZBs via URL or file upload
- **Download Queue**: Real-time queue display with pause/resume controls
- **Usenet Servers**: Configure multiple Usenet server providers
- **Categories**: Organize downloads by category with custom directories
- **History**: View completed downloads with status
- **Statistics**: Download speed, queue size, server stats
- **Backup/Restore**: Backup and restore SABnzbd configuration

## API Endpoints

### Public
- `GET /health` - Health check
- `GET /status` - Service status with queue info

### Protected (JWT required)

#### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

#### Queue Management
- `GET /queue` - Get download queue
- `POST /nzb/add` - Add NZB from URL
- `POST /nzb/upload` - Upload NZB file
- `DELETE /queue/{id}` - Remove from queue
- `POST /queue/{id}/pause` - Pause item
- `POST /queue/{id}/resume` - Resume item
- `POST /queue/pause` - Pause entire queue
- `POST /queue/resume` - Resume entire queue

#### History
- `GET /history` - Get download history
- `DELETE /history/{id}` - Delete history item
- `POST /history/clear` - Clear all history

#### Categories
- `GET /categories` - List categories
- `POST /category` - Add/update category
- `DELETE /category/{name}` - Delete category

#### Usenet Servers
- `GET /servers` - List configured servers
- `POST /server` - Add/update server
- `DELETE /server/{name}` - Delete server

#### Statistics
- `GET /stats` - Get download statistics

#### Container
- `GET /container/status` - Container status
- `POST /container/install` - Install SABnzbd
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container
- `POST /container/update` - Update to latest image
- `DELETE /container` - Uninstall container

#### Logs & Backup
- `GET /logs` - Get container logs
- `POST /backup` - Create backup
- `POST /restore` - Restore from backup

## Configuration

Configuration is stored in `/etc/secubox/newsbin.toml`:

```toml
enabled = true
image = "lscr.io/linuxserver/sabnzbd:latest"
port = 8090
data_path = "/srv/newsbin"
downloads_path = "/srv/downloads/usenet"
timezone = "Europe/Paris"
domain = "newsbin.secubox.local"
haproxy = false
```

## Paths

- **API**: `/usr/lib/secubox/newsbin/api/`
- **Web UI**: `/usr/share/secubox/www/newsbin/`
- **Config**: `/etc/secubox/newsbin.toml`
- **Data**: `/srv/newsbin/` (SABnzbd config)
- **Downloads**: `/srv/downloads/usenet/` (completed/incomplete)
- **Socket**: `/run/secubox/newsbin.sock`

## Usage

### Install SABnzbd

From the web UI or via API:
```bash
curl -X POST http://localhost/api/v1/newsbin/container/install \
  -H "Authorization: Bearer $TOKEN"
```

### Add Usenet Server

Configure your Usenet provider:
```bash
curl -X POST http://localhost/api/v1/newsbin/server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyProvider",
    "host": "news.provider.com",
    "port": 563,
    "ssl": true,
    "username": "user",
    "password": "pass",
    "connections": 10
  }'
```

### Add NZB

```bash
curl -X POST http://localhost/api/v1/newsbin/nzb/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/file.nzb",
    "category": "movies"
  }'
```

## Theme

Uses P31 Phosphor light theme with yellow accent color (#eab308) for Newsbin branding.

## Requirements

- secubox-core
- Docker or Podman
- python3-uvicorn

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
