# secubox-glances

SecuBox Glances system monitoring module - wraps the Glances monitoring tool.

## Description

This module provides a web interface for system monitoring using Glances and psutil.
It collects real-time CPU, memory, disk, network stats with historical data collection.

## Features

- Real-time system statistics (CPU, memory, disk, network)
- Process list with sorting
- Hardware sensors (temperature, fans, battery)
- Historical data collection (24h by default)
- Service control (start/stop/restart Glances daemon)
- P31 Phosphor light theme UI

## API Endpoints

### Public (no auth)
- `GET /api/v1/glances/health` - Health check
- `GET /api/v1/glances/status` - Service status
- `GET /api/v1/glances/stats` - Current system stats
- `GET /api/v1/glances/summary` - Dashboard summary

### Protected (JWT required)
- `GET /api/v1/glances/processes` - Top processes
- `GET /api/v1/glances/sensors` - Hardware sensors
- `GET /api/v1/glances/history` - Historical stats
- `GET /api/v1/glances/disk_io` - Disk I/O stats
- `GET /api/v1/glances/network_interfaces` - Network interface details
- `POST /api/v1/glances/start` - Start Glances service
- `POST /api/v1/glances/stop` - Stop Glances service
- `POST /api/v1/glances/restart` - Restart Glances service
- `GET /api/v1/glances/config` - Get configuration
- `POST /api/v1/glances/config` - Update configuration
- `GET /api/v1/glances/logs` - Service logs

## Dependencies

- secubox-core (>= 1.0)
- glances
- python3-psutil

## Configuration

Configuration is stored in `/etc/secubox/glances.toml`:

```toml
[glances]
refresh_interval = 3
enable_history = true
history_size = 1440
process_top_n = 15
sensors_enabled = true
disk_paths = ["/"]
```

## Web Interface

Access the dashboard at `https://<host>:9443/glances/`

Tabs:
- **Dashboard** - Real-time gauges, charts, load average
- **Processes** - Process list with sorting
- **Sensors** - Temperature, fan, battery sensors
- **Config** - Configuration and service logs

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
