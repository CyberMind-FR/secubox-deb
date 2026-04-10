# SecuBox UI Manager

Unified UI management system for SecuBox with automatic mode selection, graceful fallback, and hypervisor optimization.

## Features

- **Three UI Modes**:
  - **KUI** (Kiosk UI): X11 + Chromium fullscreen kiosk
  - **TUI** (Terminal UI): Textual-based console application
  - **Console**: Standard getty login fallback

- **Automatic Detection**:
  - Hypervisor detection (VirtualBox, QEMU/KVM, VMware, bare metal)
  - Display capabilities (X11, Wayland, framebuffer, TTY)
  - Graphics hardware and driver selection

- **Graceful Fallback**:
  - Priority chain: KUI → TUI → Console
  - Automatic retry with configurable limits
  - Console mode always succeeds (terminal state)

- **Health Monitoring**:
  - Periodic health checks for running mode
  - Automatic fallback on failure detection
  - Configurable failure threshold

- **Modular Debug System**:
  - 6 verbosity levels (SILENT → TRACE)
  - Component-based filtering
  - Multiple output channels (journald, console, FIFO)

## Installation

```bash
apt install secubox-ui-manager
```

## Usage

### Command Line

```bash
# Auto-detect and start (default)
secubox-ui-manager

# Force specific mode
secubox-ui-manager --mode tui

# Enable debug logging
secubox-ui-manager --debug 4

# Show current status
secubox-ui-manager --status

# Reset state machine
secubox-ui-manager --reset
```

### Kernel Command Line

Override UI mode via kernel parameters:

```
secubox.ui=tui    # Force TUI mode
secubox.ui=kui    # Force KUI mode
secubox.ui=console # Force console mode
```

### Environment Variables

```bash
# Debug level (0-5)
export SECUBOX_UI_DEBUG=4

# Filter components (comma-separated)
export SECUBOX_UI_DEBUG_COMPONENTS=state,kui,health
```

## Configuration

Configuration file: `/etc/secubox/ui/ui.toml`

```toml
[general]
default_mode = "auto"

[fallback]
priority = ["kui", "tui", "console"]
timeout_seconds = 30
max_retries = 2

[debug]
level = 1
components = []

[kui]
user = "kiosk"
url = "http://127.0.0.1:8080/"
vt = 7
disable_gpu = true

[health]
check_interval = 10.0
failure_threshold = 3
```

## Debug Levels

| Level | Name   | Description |
|-------|--------|-------------|
| 0     | SILENT | No output |
| 1     | ERROR  | Errors only |
| 2     | WARN   | Warnings and errors |
| 3     | INFO   | Informational messages |
| 4     | DEBUG  | Debug traces |
| 5     | TRACE  | Full trace including syscalls |

## Architecture

```
secubox-ui-manager/
├── ui/
│   ├── __init__.py          # Package exports
│   ├── manager.py           # Main orchestrator
│   ├── lib/
│   │   ├── debug.py         # Modular debug system
│   │   ├── state_machine.py # UI state machine
│   │   ├── hypervisor.py    # VM detection & config
│   │   ├── display.py       # Display capabilities
│   │   ├── fallback.py      # Fallback chain logic
│   │   └── health.py        # Health monitoring
│   ├── drivers/
│   │   ├── kui_driver.py    # KUI (X11+Chromium)
│   │   ├── tui_driver.py    # TUI (Textual)
│   │   └── console_driver.py # Console (getty)
│   └── config/
│       └── ui.toml          # Default configuration
├── bin/
│   └── secubox-ui-manager   # CLI entry point
└── debian/                  # Debian packaging
```

## State Machine

```
INIT → DETECTING → SELECTING → [KUI|TUI|CONSOLE]_STARTING
                                        ↓ success
                               [KUI|TUI|CONSOLE]_OK
                                        ↓ failure
                                    FALLBACK → next mode
                                        ↓ all failed
                                      ERROR
```

## Hypervisor Optimization

| Hypervisor | Driver | 3D | Resolution | Notes |
|------------|--------|-----|------------|-------|
| VirtualBox | modesetting | OFF | 1280x720 | vboxvideo too slow |
| QEMU/KVM | modesetting | ON* | native | *with virtio-gpu |
| VMware | vmware | ON | native | Full acceleration |
| Bare metal | auto | ON | native | Hardware detection |

## Files

- `/etc/secubox/ui/ui.toml` - User configuration
- `/run/secubox/ui/state.json` - Current state
- `/run/secubox/ui/health.json` - Health status
- `/run/secubox/ui/debug.fifo` - Debug FIFO for tools

## systemd Integration

```bash
# Service status
systemctl status secubox-ui-manager

# View logs
journalctl -u secubox-ui-manager -f

# Restart
systemctl restart secubox-ui-manager
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr

## License

Proprietary / ANSSI CSPN candidate
