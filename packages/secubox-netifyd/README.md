# SecuBox Netifyd

Network Intelligence Daemon management module for SecuBox-DEB. Provides a web dashboard and REST API for deep packet inspection using the netifyd daemon.

## Overview

Netifyd is a network intelligence daemon that performs deep packet inspection (DPI) to identify applications and protocols in network traffic. This SecuBox module wraps the netifyd Unix socket interface and provides:

- Real-time network flow visualization
- Protocol and application detection
- Device/host discovery and tracking
- Bandwidth monitoring per application/device
- DPI alerts and notifications
- Service management (start/stop/restart)

## Architecture

```
+------------------+     +-------------------+     +------------+
| Web Dashboard    | --> | FastAPI Backend   | --> | netifyd    |
| (P31 Phosphor)   |     | /api/v1/netifyd   |     | daemon     |
+------------------+     +-------------------+     +------------+
        |                        |                       |
        v                        v                       v
   Browser/UI            Unix Socket API          Network Interfaces
                    /run/secubox/netifyd.sock    /run/netifyd/netifyd.sock
```

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Daemon status, version, running state

### Service Control
- `POST /start` - Start netifyd daemon
- `POST /stop` - Stop netifyd daemon
- `POST /restart` - Restart netifyd daemon

### Configuration
- `GET /config` - Current configuration
- `POST /config` - Update configuration

### Network Flows
- `GET /flows` - Active network flows
- `GET /flows/top` - Top flows by bandwidth

### Protocol & Application Detection
- `GET /protocols` - Detected protocols list
- `GET /applications` - Detected applications

### Device Discovery
- `GET /hosts` - Known hosts/devices

### Statistics
- `GET /stats` - Traffic statistics (cached)
- `GET /stats/realtime` - Real-time interface statistics

### Alerts
- `GET /alerts` - DPI alerts
- `POST /alerts/dismiss` - Dismiss an alert
- `POST /alerts/dismiss_all` - Dismiss all alerts
- `DELETE /alerts/clear` - Clear dismissed alerts

### Logs
- `GET /logs` - Recent daemon logs

### Three-fold Architecture
- `GET /module/info` - Module information
- `GET /module/health` - Module health status
- `GET /module/capabilities` - Module capabilities

### Export
- `GET /export/flows` - Export flows (JSON/CSV)

## Installation

```bash
apt install secubox-netifyd
```

## Dependencies

- `secubox-core` - SecuBox core library (auth, config, logging)
- `netifyd` - Network Intelligence Daemon

## Configuration

Configuration is stored in `/etc/secubox/netifyd.json`:

```json
{
  "interface": "eth0",
  "listen_address": "127.0.0.1",
  "listen_port": 7150,
  "enable_socket": true,
  "enable_sink": false,
  "sink_url": "",
  "update_interval": 60
}
```

## Files

- `/usr/lib/secubox/netifyd/api/` - FastAPI backend
- `/usr/share/secubox/www/netifyd/` - Web dashboard
- `/etc/nginx/secubox.d/netifyd.conf` - Nginx proxy config
- `/run/secubox/netifyd.sock` - API Unix socket
- `/var/lib/secubox/netifyd/` - Data directory (stats cache, alerts)

## Systemd Service

```bash
# Start the service
systemctl start secubox-netifyd

# Check status
systemctl status secubox-netifyd

# View logs
journalctl -u secubox-netifyd -f
```

## Web Dashboard

Access the dashboard at: `https://<secubox-ip>/netifyd/`

Features:
- Real-time flow table with application/protocol detection
- Top applications by bandwidth with progress bars
- Top protocols by traffic volume
- Device list with MAC, IP, and bandwidth usage
- Interface statistics (RX/TX bytes, packets, errors)
- Alert management with dismiss/clear actions
- Service controls (start/stop/restart)
- Log viewer modal

## Netifyd Socket Communication

The module communicates with netifyd via Unix socket at `/run/netifyd/netifyd.sock` using JSON-RPC style messages:

```json
// Request
{"type": "get_flows"}

// Response
{"flows": [...]}
```

Supported commands:
- `get_flows` - Get active network flows
- `get_applications` - Get detected applications
- `get_protocols` - Get detected protocols
- `get_devices` - Get discovered devices
- `get_stats` - Get daemon statistics
- `get_risks` - Get detected risks/alerts
- `get_top_talkers` - Get top bandwidth consumers

## Background Tasks

A background task runs every 60 seconds to:
1. Refresh interface statistics from `/sys/class/net/<iface>/statistics`
2. Aggregate flow data by application, protocol, and device
3. Cache statistics to disk for fast retrieval
4. Update the in-memory stats cache

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
SecuBox - https://secubox.in

## License

Proprietary / ANSSI CSPN candidate
