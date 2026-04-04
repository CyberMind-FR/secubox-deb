# secubox-webradio

Internet Radio Streaming and Management for SecuBox-DEB.

## Overview

This package provides a complete internet radio management solution including:

- **Station Management**: Save and organize favorite radio stations
- **Streaming Server**: Icecast/Liquidsoap via Docker/Podman containers
- **Recording**: Record streams in MP3, OGG, or AAC formats
- **Scheduling**: Program playback and recording schedules
- **Web Player**: Built-in audio player with visualizer

## Features

- P31 Phosphor light theme with violet (#8b5cf6) accent
- Genre-based station filtering
- Weekly schedule calendar view
- Audio visualizer
- Container management for Icecast
- Multiple output formats support

## API Endpoints

### Public (no auth)
- `GET /api/v1/webradio/health` - Health check
- `GET /api/v1/webradio/status` - Service status

### Protected (JWT required)

#### Stations
- `GET /api/v1/webradio/stations` - List favorite stations
- `POST /api/v1/webradio/station/add` - Add station to favorites
- `DELETE /api/v1/webradio/station/{id}` - Remove station
- `GET /api/v1/webradio/station/{id}` - Get station details
- `GET /api/v1/webradio/station/{id}/play` - Get stream URL

#### Streaming
- `POST /api/v1/webradio/stream/start` - Start streaming server
- `POST /api/v1/webradio/stream/stop` - Stop streaming
- `GET /api/v1/webradio/stream/status` - Streaming status with mounts

#### Recordings
- `GET /api/v1/webradio/recordings` - List recordings
- `POST /api/v1/webradio/record/start` - Start recording
- `POST /api/v1/webradio/record/stop` - Stop recording
- `DELETE /api/v1/webradio/recording/{filename}` - Delete recording

#### Schedule
- `GET /api/v1/webradio/schedule` - Get schedule
- `POST /api/v1/webradio/schedule` - Add/update schedule entry
- `DELETE /api/v1/webradio/schedule/{id}` - Delete entry

#### Container Management
- `GET /api/v1/webradio/container/status` - Docker/Podman status
- `POST /api/v1/webradio/container/install` - Pull container images
- `POST /api/v1/webradio/container/start` - Start containers
- `POST /api/v1/webradio/container/stop` - Stop containers
- `POST /api/v1/webradio/container/restart` - Restart containers

#### Configuration
- `GET /api/v1/webradio/config` - Get configuration
- `POST /api/v1/webradio/config` - Update configuration
- `GET /api/v1/webradio/logs` - Get container logs

## Configuration

Configuration file: `/etc/secubox/webradio.toml`

```toml
icecast_port = 8000
liquidsoap_port = 8001
data_path = "/var/lib/secubox/webradio"
output_formats = ["mp3", "ogg", "aac"]
max_recording_hours = 4
memory_limit = "256m"
```

## Data Storage

- Stations: `/var/lib/secubox/webradio/stations.json`
- Schedule: `/var/lib/secubox/webradio/schedule.json`
- Recordings: `/var/lib/secubox/webradio/recordings/`
- Icecast config: `/var/lib/secubox/webradio/icecast/`
- Logs: `/var/lib/secubox/webradio/logs/`

## Dependencies

- `secubox-core` - Core library with JWT auth
- `python3-uvicorn` - ASGI server
- `python3-httpx` - HTTP client
- `ffmpeg` - For recording (recommended)
- `podman` or `docker.io` - Container runtime (recommended)

## Frontend

The web interface is available at `/webradio/` and provides:

- **Player Tab**: Now playing display and quick station access
- **Stations Tab**: Add/manage favorite stations with genre filtering
- **Streaming Tab**: Control Icecast server and view active mounts
- **Recordings Tab**: Record stations and manage saved recordings
- **Schedule Tab**: Weekly calendar for programmed playback/recording
- **Settings Tab**: Configuration, container status, and logs

## Building

```bash
cd packages/secubox-webradio
dpkg-buildpackage -us -uc -b
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
