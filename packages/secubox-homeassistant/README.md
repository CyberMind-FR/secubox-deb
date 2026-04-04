# secubox-homeassistant

Home Assistant IoT Hub module for SecuBox-DEB.

## Description

This module provides a comprehensive interface for managing Home Assistant on SecuBox. It supports multiple deployment options including Docker, Podman, and LXC containers.

## Features

- **Container Management**: Install, start, stop, and restart Home Assistant
- **Docker/Podman/LXC Support**: Choose your preferred container runtime
- **Entity Browser**: View and control all Home Assistant entities
- **Automation Management**: Enable/disable automations with toggle switches
- **Scene Control**: Browse and activate scenes
- **HACS Integration**: Install the Home Assistant Community Store
- **Backup & Restore**: Create and restore configuration backups
- **Logs Viewer**: Real-time log monitoring

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

### Entities
- `GET /entities` - List all entities
- `GET /entity/{id}` - Get entity details
- `POST /entity/{id}/command` - Send command to entity

### Devices
- `GET /devices` - List all devices

### Integrations
- `GET /integrations` - List integrations
- `POST /integration/install` - Install integration

### Automations
- `GET /automations` - List automations
- `POST /automation/toggle` - Enable/disable automation

### Scenes
- `GET /scenes` - List scenes
- `POST /scene/{id}/activate` - Activate scene

### Add-ons
- `GET /addons` - List add-ons
- `POST /addon/install` - Install add-on
- `POST /hacs/install` - Install HACS

### Backup
- `POST /backup/create` - Create backup
- `GET /backups` - List backups
- `POST /backup/restore` - Restore from backup

### Container Management
- `GET /container/status` - Container status
- `POST /container/install` - Install container/pull image
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container

### Logs
- `GET /logs` - Get recent logs

## Installation

```bash
apt install secubox-homeassistant
```

## Configuration

Configuration is stored in `/etc/secubox/homeassistant.toml`:

```toml
ha_url = "http://127.0.0.1:8123"
token = ""
container_name = "homeassistant"
container_type = "docker"  # docker, podman, or lxc
image = "ghcr.io/home-assistant/home-assistant:stable"
port = 8123
timezone = "UTC"
```

## Data Directories

- `/srv/homeassistant/config` - Home Assistant configuration
- `/srv/homeassistant/backups` - Backup files
- `/var/cache/secubox/homeassistant` - Cache files

## Dependencies

- secubox-core (>= 1.0)
- python3-uvicorn
- python3-httpx
- docker.io or podman (recommended)
- lxc (optional, for LXC deployment)

## Theme

Uses the P31 phosphor light theme with Home Assistant blue accent (#03a9f4).

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
