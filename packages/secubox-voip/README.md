# secubox-voip

VoIP/PBX management module for SecuBox-DEB. Manages Asterisk/FreePBX Docker container with full PBX functionality.

## Features

- **Container Management**: Install, start, stop, restart FreePBX Docker container
- **Extension Management**: Create, configure, and delete SIP extensions
- **Trunk Configuration**: Set up SIP/PJSIP/IAX2 trunks to VoIP providers
- **Route Management**: Configure inbound and outbound call routing
- **IVR Builder**: Create interactive voice response menus
- **Voicemail**: Manage voicemail boxes for extensions
- **CDR**: View call detail records and call history
- **Active Calls**: Monitor current calls in real-time
- **SIP Status**: View SIP endpoint registration status

## API Endpoints

### Public
- `GET /api/v1/voip/health` - Health check
- `GET /api/v1/voip/status` - Service status and statistics

### Protected (JWT required)
- `GET /api/v1/voip/config` - Get configuration
- `POST /api/v1/voip/config` - Update configuration

### Extensions
- `GET /api/v1/voip/extensions` - List all extensions
- `POST /api/v1/voip/extension` - Create extension
- `DELETE /api/v1/voip/extension/{number}` - Delete extension

### Trunks
- `GET /api/v1/voip/trunks` - List all trunks
- `POST /api/v1/voip/trunk` - Create trunk
- `DELETE /api/v1/voip/trunk/{id}` - Delete trunk

### Routes
- `GET /api/v1/voip/routes/inbound` - List inbound routes
- `GET /api/v1/voip/routes/outbound` - List outbound routes
- `POST /api/v1/voip/route` - Create route
- `DELETE /api/v1/voip/route/{id}` - Delete route

### IVR
- `GET /api/v1/voip/ivr` - List IVR menus
- `POST /api/v1/voip/ivr` - Create IVR menu
- `DELETE /api/v1/voip/ivr/{id}` - Delete IVR menu

### Voicemail & CDR
- `GET /api/v1/voip/voicemail` - List voicemail boxes
- `GET /api/v1/voip/cdr` - Get call detail records

### SIP Status
- `GET /api/v1/voip/sip/peers` - Get SIP endpoint status
- `GET /api/v1/voip/channels` - Get active calls

### Container Control
- `GET /api/v1/voip/container/status` - Container status
- `POST /api/v1/voip/container/install` - Install FreePBX
- `POST /api/v1/voip/container/start` - Start container
- `POST /api/v1/voip/container/stop` - Stop container
- `POST /api/v1/voip/container/restart` - Restart container
- `POST /api/v1/voip/container/uninstall` - Remove container

### Logs
- `GET /api/v1/voip/logs` - Get container logs

## Configuration

Configuration file: `/etc/secubox/voip.toml`

```toml
enabled = true
image = "tiredofit/freepbx:latest"
http_port = 8180
sip_port = 5060
rtp_start = 10000
rtp_end = 20000
data_path = "/srv/voip"
timezone = "Europe/Paris"
domain = "voip.secubox.local"
haproxy = false
```

## Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8180 | TCP | FreePBX web interface (localhost only) |
| 5060 | UDP/TCP | SIP signaling |
| 5061 | TCP | SIP TLS |
| 10000-20000 | UDP | RTP media |

## Data Storage

- `/srv/voip/data` - FreePBX data and database
- `/srv/voip/logs` - Asterisk and FreePBX logs
- `/srv/voip/cdr` - Call detail records (CSV)
- `/etc/secubox/voip-extensions.json` - Extension configuration
- `/etc/secubox/voip-trunks.json` - Trunk configuration
- `/etc/secubox/voip-routes.json` - Route configuration
- `/etc/secubox/voip-ivr.json` - IVR configuration

## Development

```bash
# Run API locally
cd packages/secubox-voip
uvicorn api.main:app --reload --uds /tmp/voip.sock

# Build package
dpkg-buildpackage -us -uc -b
```

## Dependencies

- secubox-core >= 1.0
- python3-uvicorn
- docker.io or podman (recommended)

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
