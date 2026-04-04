# secubox-photoprism

SecuBox module for PhotoPrism photo management via Docker/Podman container.

## Features

- **PhotoPrism Container Management** - Install, start, stop, restart, update via Docker/Podman
- **Library Indexing** - Scan and index photo library with AI-powered metadata extraction
- **Face Recognition** - Toggle AI-powered face detection and grouping
- **Album Management** - Create and manage photo albums
- **Import Workflow** - Import photos from designated folder
- **Storage Monitoring** - Track disk usage and storage paths
- **User Management** - Manage PhotoPrism users
- **Backup/Restore** - Create and restore configuration backups

## API Endpoints

All endpoints require JWT authentication except `/health` and `/status`.

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status with library statistics

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

### Library
- `GET /library/stats` - Library statistics
- `POST /library/index` - Start indexing
- `POST /library/import` - Import photos

### Albums
- `GET /albums` - List albums
- `POST /album/create` - Create album
- `DELETE /album/{album_id}` - Delete album

### Face Recognition
- `GET /faces` - Face recognition status
- `POST /faces/enable` - Enable face recognition
- `POST /faces/disable` - Disable face recognition

### Storage
- `GET /storage` - Storage information

### Users
- `GET /users` - List users
- `POST /user` - Create user
- `DELETE /user/{username}` - Delete user

### Container
- `GET /container/status` - Container status
- `POST /container/install` - Install PhotoPrism
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container
- `POST /container/uninstall` - Uninstall container
- `POST /container/update` - Update to latest image

### Logs & Backup
- `GET /logs` - Container logs
- `POST /backup` - Create backup
- `POST /restore` - Restore from backup

## Configuration

Configuration file: `/etc/secubox/photoprism.toml`

```toml
enabled = false
image = "photoprism/photoprism:latest"
port = 2342
data_path = "/srv/photoprism"
originals_path = "/srv/photoprism/originals"
import_path = "/srv/photoprism/import"
timezone = "Europe/Paris"
domain = "photos.secubox.local"
haproxy = false
face_recognition = true
experimental = false
readonly = false
public = false
```

## Directory Structure

```
/srv/photoprism/
├── originals/     # Original photos (mounted in container)
├── import/        # Photos to import
└── storage/       # PhotoPrism database and cache
```

## Usage

1. Install the package: `apt install secubox-photoprism`
2. Open the web interface at `/photoprism/`
3. Click "Install" to download and setup PhotoPrism
4. Click "Start" to run the container
5. Add photos to `/srv/photoprism/import/`
6. Click "Import Photos" to add them to your library
7. Click "Index Library" to process and extract metadata

## Dependencies

- Docker or Podman (recommended: docker.io)
- secubox-core
- python3-uvicorn

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
