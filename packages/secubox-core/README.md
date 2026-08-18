<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Core

Core package for SecuBox-Deb platform. Provides shared libraries, utilities, and base services.

## Components

### Python Library (`secubox_core`)

Shared Python modules for all SecuBox services:

- `auth.py` - JWT authentication helpers
- `config.py` - TOML configuration loader
- `logger.py` - Unified logging
- `system.py` - System utilities
- `kiosk.py` - Kiosk mode helpers

### Services

| Service | Description |
|---------|-------------|
| `secubox-core.service` | Core initialization |
| `secubox-runtime.service` | Runtime directory setup |
| `secubox-led-heartbeat.service` | LED heartbeat indicator |

### CLI Tools

- `/usr/bin/secubox` - Main SecuBox CLI
- `/usr/bin/secubox-firstboot` - First boot initialization
- `/usr/sbin/secubox-led-heartbeat` - LED heartbeat daemon

## LED Heartbeat

Visual system status indicator using IS31FL3199 RGB LEDs on MOCHAbin.

### Configuration

Environment variables in systemd service:

```ini
Environment=LED_COLOR=green   # red, green, or blue
Environment=LED_NUM=1         # LED number (1-3)
```

### Pattern

Double-pulse heartbeat pattern:
- ON 150ms → OFF 150ms → ON 150ms → OFF 700ms (repeat)

### Manual Control

```bash
# Start/stop
systemctl start secubox-led-heartbeat
systemctl stop secubox-led-heartbeat

# Test LED manually
echo 255 > /sys/class/leds/green:led1/brightness
echo 0 > /sys/class/leds/green:led1/brightness
```

## Installation

```bash
apt install secubox-core
```

## Dependencies

- python3
- python3-toml
- i2c-tools (for LED control)

## Files

```
/usr/lib/python3/dist-packages/secubox_core/
/usr/bin/secubox
/usr/bin/secubox-firstboot
/usr/sbin/secubox-led-heartbeat
/usr/lib/systemd/system/secubox-*.service
/usr/share/secubox-core/nginx/
/etc/nginx/secubox.d/
```

## License

Proprietary - CyberMind / ANSSI CSPN candidate
