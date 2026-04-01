# SecuBox Console TUI

Terminal-based dashboard for SecuBox appliances using Python Textual framework.

## Features

- **Dashboard**: Live system metrics (CPU, memory, disk), uptime, health score
- **Services**: List, start, stop, restart, enable, disable SecuBox services
- **Network**: Interface status with WAN/LAN/SFP classification
- **Logs**: Real-time log viewer with unit filtering
- **Menu**: System info, quick actions (reboot, shutdown, kiosk toggle)

## Keyboard Navigation

| Key | Action |
|-----|--------|
| `d` | Switch to Dashboard |
| `s` | Switch to Services |
| `n` | Switch to Network |
| `l` | Switch to Logs |
| `m` | Switch to Menu |
| `q` | Quit |
| `r` | Refresh current view |
| `j` | Move down (vim-style) |
| `k` | Move up (vim-style) |
| `h` | Go back |
| `Enter` | Select/toggle |
| `?` | Help |

## Services Screen Actions

| Key | Action |
|-----|--------|
| `Enter` | Toggle service (start if stopped, stop if running) |
| `R` | Restart selected service |
| `e` | Enable selected service |
| `D` | Disable selected service |

## Board-Specific Theming

The console automatically detects the board type and applies themed colors:

| Board | Color | Badge |
|-------|-------|-------|
| MOCHAbin | Sky Blue | PRO |
| ESPRESSObin v7 | Green | LITE |
| ESPRESSObin Ultra | Teal | ULTRA |
| x64 VM | Purple | VM |
| x64 Baremetal | Orange | SERVER |
| Raspberry Pi | Pink | PI |

## Installation

```bash
apt install secubox-console
```

## Usage

### Manual Launch

```bash
secubox-console
```

### Auto-Start on TTY1

Enable console mode to auto-start on TTY1 at boot:

```bash
secubox-kiosk-setup console
```

This disables GUI kiosk mode if active and enables the console TUI service.

### Check Current Mode

```bash
secubox-kiosk-setup status
```

### Disable Console Mode

```bash
secubox-kiosk-setup no-console
```

## systemd Service

The console runs as a systemd service on TTY1:

```bash
# Check status
systemctl status secubox-console

# Start manually
systemctl start secubox-console

# View logs
journalctl -u secubox-console -f
```

## Dependencies

- `secubox-core` >= 1.1.0 (board detection, kiosk management)
- `python3-textual` >= 0.40.0 (TUI framework)
- `python3-httpx` (async HTTP client)
- `python3-rich` (terminal formatting)

## API Communication

The console communicates with SecuBox modules via Unix sockets:

- `/run/secubox/hub.sock` - Dashboard data, services
- `/run/secubox/system.sock` - Board info, resources
- `/run/secubox/watchdog.sock` - Health status
- `/run/secubox/netmodes.sock` - Network mode

If sockets are unavailable, the console falls back to local system commands.

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
