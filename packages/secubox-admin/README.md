# secubox-admin

Advanced system administration dashboard for SecuBox.

## Overview

secubox-admin provides a centralized interface for system administration tasks including service management, log viewing, storage monitoring, and system updates. All actions are logged to the CSPN-compliant audit log.

## Features

- **Service Management**: Start, stop, restart, enable, disable systemd services
- **Log Viewer**: Real-time journalctl log streaming with unit filtering
- **Process Monitor**: View running processes with CPU/memory usage
- **Storage Overview**: Disk usage, mount points, SMART health status
- **Update Management**: APT package updates with security patch tracking
- **System Actions**: Reboot/shutdown with confirmation and audit logging
- **CSPN Audit Logging**: All administrative actions logged to `/var/log/secubox/audit.log`

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/status` | GET | No | System overview |
| `/services` | GET | JWT | List all systemd services |
| `/service/{name}/start` | POST | JWT | Start a service |
| `/service/{name}/stop` | POST | JWT | Stop a service |
| `/service/{name}/restart` | POST | JWT | Restart a service |
| `/service/{name}/enable` | POST | JWT | Enable a service |
| `/service/{name}/disable` | POST | JWT | Disable a service |
| `/logs` | GET | JWT | Get system logs |
| `/storage` | GET | JWT | Storage/disk information |
| `/processes` | GET | JWT | Running processes |
| `/updates` | GET | JWT | Available APT updates |
| `/updates/apply` | POST | JWT | Apply updates |
| `/reboot` | POST | JWT | Reboot system (requires confirm) |
| `/shutdown` | POST | JWT | Shutdown system (requires confirm) |

## Frontend

The web interface is available at `/admin/` and provides:

- **Dashboard**: System overview with health indicators
- **Services Tab**: Service list with action buttons
- **Logs Tab**: Real-time log viewer with filtering
- **Storage Tab**: Disk usage with progress bars
- **Processes Tab**: Top processes by CPU/memory
- **Updates Tab**: Security updates with apply button
- **System Tab**: Reboot/shutdown controls

### Color Scheme

Uses an orange accent color to distinguish administrative functions from monitoring modules:
- Primary accent: `#f97316` (orange)
- Background: P31 Phosphor light theme
- Warnings/errors: Standard SecuBox palette

## Security

### CSPN Audit Logging

All administrative actions are logged to `/var/log/secubox/audit.log`:

```
[2026-04-04T10:30:45.123456] ADMIN user=admin action=service_restart service=nginx
[2026-04-04T10:32:00.654321] ADMIN user=admin action=reboot reason="Kernel update"
```

### Service Privileges

This module runs as root to allow service management. Ensure proper JWT authentication is configured.

### Action Confirmation

Dangerous actions (reboot, shutdown, service stop) require explicit confirmation via the `confirm: true` parameter.

## Installation

```bash
apt install secubox-admin python3-psutil
systemctl enable --now secubox-admin
```

## Dependencies

- `python3-psutil`: Process and system utilities
- `systemd`: Service management via systemctl
- `journalctl`: Log access
- `apt`: Package management

## Configuration

Configuration is stored in `/etc/secubox/admin.toml`:

```toml
[admin]
# Services to highlight in the dashboard
priority_services = ["nginx", "secubox-hub", "secubox-portal"]

# Maximum log lines to return
max_log_lines = 1000

# Update check interval (seconds)
update_check_interval = 3600
```

## License

Proprietary - CyberMind SecuBox
ANSSI CSPN certification candidate
