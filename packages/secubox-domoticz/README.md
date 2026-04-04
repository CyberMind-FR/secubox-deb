# SecuBox Domoticz

Home automation system management module for SecuBox-DEB.

## Features

- **Container Management**: Docker/Podman-based Domoticz deployment
- **Device Management**: Control switches, sensors, lights, and more
- **Room Organization**: Group devices by room/location
- **Scene Control**: Create and activate automation scenes
- **Hardware Support**: Z-Wave, Zigbee, 433MHz, MQTT protocols
- **Event Logging**: Track all device events and changes
- **Graphs**: Visualize sensor data over time
- **Notifications**: Email, Telegram, Pushover alerts
- **Backup/Restore**: Full configuration backup support

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status and statistics

### Devices
- `GET /devices` - List all devices
- `GET /device/{idx}` - Device details
- `POST /device/{idx}/command` - Send command (On/Off/Toggle/Set Level)

### Rooms
- `GET /rooms` - List rooms
- `POST /room` - Create room
- `DELETE /room/{idx}` - Delete room

### Scenes
- `GET /scenes` - List scenes
- `POST /scene/{idx}/activate` - Activate/deactivate scene

### Hardware
- `GET /hardware` - List hardware controllers
- `POST /hardware` - Add hardware
- `DELETE /hardware/{idx}` - Remove hardware

### Events & Graphs
- `GET /events` - Event log
- `GET /graphs/{idx}` - Device graph data

### Notifications
- `GET /notifications` - Get notification settings
- `POST /notifications` - Update settings

### Container Control
- `GET /container/status` - Container status
- `POST /container/install` - Pull Domoticz image
- `POST /container/start` - Start container
- `POST /container/stop` - Stop container
- `POST /container/restart` - Restart container

### Logs & Backup
- `GET /logs` - Container logs
- `POST /backup` - Create backup
- `GET /backups` - List backups
- `POST /restore` - Restore from backup

## Installation

```bash
apt install secubox-domoticz
```

## Configuration

Configuration is stored in `/etc/secubox/domoticz.toml`:

```toml
port = 8080
timezone = "Europe/Paris"
mqtt_enabled = false
mqtt_host = "127.0.0.1"
mqtt_port = 1883
mqtt_topic = "domoticz"
```

## Data Storage

- Container data: `/srv/domoticz/`
- Configuration: `/srv/domoticz/config/`
- Scripts: `/srv/domoticz/scripts/`
- Plugins: `/srv/domoticz/plugins/`
- Backups: `/var/lib/secubox/backups/domoticz/`

## Supported Hardware

- **Z-Wave**: USB dongles (Aeotec, Zooz, etc.)
- **Zigbee**: USB coordinators (CC2531, CC2652, etc.)
- **433MHz**: RFXtrx433 and compatible
- **MQTT**: Integration with Home Assistant, Zigbee2MQTT, etc.
- **HTTP/TCP**: IP-based devices

## Theme

Uses the SecuBox P31 phosphor light theme with cyan (#06b6d4) accents.

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
