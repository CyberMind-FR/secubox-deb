# SecuBox Eye Remote

**Version:** 2.0.0
**Hardware:** Raspberry Pi Zero W + HyperPixel 2.1 Round (480x480)
**Purpose:** Physical dashboard display for SecuBox monitoring

## Overview

SecuBox Eye Remote is a dedicated hardware display module that connects to a SecuBox appliance via USB OTG or WiFi. It provides real-time system metrics visualization on a circular 480x480 LCD display.

```
┌─────────────────────────────────────────────────────────────┐
│                     SecuBox Eye Remote                      │
│                                                             │
│   ┌─────────────┐      USB OTG       ┌─────────────────┐   │
│   │  SecuBox    │◄──────────────────►│  RPi Zero W     │   │
│   │  Appliance  │    10.55.0.0/30    │  + HyperPixel   │   │
│   │             │                    │  480x480 Round  │   │
│   │  Port 8000  │      WiFi          │                 │   │
│   │  FastAPI    │◄───────────────────│  Chromium Kiosk │   │
│   └─────────────┘                    └─────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **Real-time Metrics**: CPU, memory, disk, temperature, network
- **Dual Connectivity**: USB OTG (primary) + WiFi (fallback)
- **Secure Pairing**: QR code-based device pairing with JWT auth
- **Offline Boot**: Pre-installed packages, no internet required
- **Kiosk Mode**: Auto-login, fullscreen Chromium dashboard

## Hardware Requirements

| Component | Specification |
|-----------|---------------|
| Board | Raspberry Pi Zero W (ARMv6 armhf) |
| Display | Pimoroni HyperPixel 2.1 Round Touch 480x480 |
| Connection | USB DATA port (middle micro-USB) |
| Storage | microSD 8GB+ |

## Architecture

### API Endpoints

```
/api/v1/eye-remote/
├── /devices/
│   ├── GET  /              # List paired devices
│   ├── POST /pair          # Pair new device
│   └── DELETE /{id}        # Unpair device
├── /pairing/
│   ├── POST /start         # Start pairing session
│   ├── GET  /qr            # Get QR code for pairing
│   └── POST /complete      # Complete pairing
└── /metrics/
    └── GET  /              # Get system metrics (device auth)
```

### Core Components

| Module | Purpose |
|--------|---------|
| `core/metrics.py` | System metrics collection (CPU, RAM, disk, temp) |
| `core/device_registry.py` | Paired device management with token auth |
| `core/pairing.py` | QR code pairing session management |
| `api/routers/*.py` | FastAPI route handlers |
| `models/*.py` | Pydantic request/response schemas |

### Display Stack

```
┌─────────────────────────────────────┐
│         Chromium (Kiosk)            │
├─────────────────────────────────────┤
│         Openbox (WM)                │
├─────────────────────────────────────┤
│         LightDM (Autologin)         │
├─────────────────────────────────────┤
│         X11 (fbdev driver)          │
├─────────────────────────────────────┤
│      HyperPixel DPI Framebuffer     │
├─────────────────────────────────────┤
│   hyperpixel2r-init (ST7701S SPI)   │
├─────────────────────────────────────┤
│         pigpiod (GPIO daemon)       │
└─────────────────────────────────────┘
```

## Installation

### Build SD Card Image

```bash
# Download Raspberry Pi OS Lite (armhf)
wget https://downloads.raspberrypi.com/raspios_lite_armhf/...

# Build offline image with all packages pre-installed
sudo ./remote-ui/round/build-eye-remote-image.sh \
    -i raspios-lite-armhf.img.xz \
    -s "MyWiFi" \
    -p "password" \
    -h "secubox-eye"

# Flash to SD card
sudo dd if=/tmp/secubox-eye-remote-2.0.0.img of=/dev/sdX bs=4M status=progress
```

### First Boot

1. Insert SD card into Pi Zero W with HyperPixel attached
2. Connect USB DATA port (middle) to SecuBox host
3. Wait ~60 seconds for boot
4. Dashboard appears automatically

### Network Configuration

| Interface | IP Address | Purpose |
|-----------|------------|---------|
| usb0 (Eye) | 10.55.0.2 | OTG gadget network |
| host | 10.55.0.1 | SecuBox host |

## Development

### Gateway Emulator

For development without physical SecuBox hardware:

```bash
# Install gateway tool
pip install -e tools/secubox-eye-gateway/

# Run with stress profile
secubox-eye-gateway --profile stressed --port 8765

# Profiles: idle, normal, busy, stressed
```

### Run Tests

```bash
cd packages/secubox-eye-remote
pytest tests/ -v
```

### Deploy Dashboard Update

```bash
# Copy new dashboard to running Eye Remote
scp remote-ui/round/index.html pi@10.55.0.2:/var/www/secubox-round/
ssh pi@10.55.0.2 "sudo systemctl restart nginx"
```

## Configuration

### SecuBox Host (`/etc/secubox/eye-remote.toml`)

```toml
[eye_remote]
enabled = true
bind = "0.0.0.0"
port = 8000

[eye_remote.otg]
network = "10.55.0.0/30"
host_ip = "10.55.0.1"
peer_ip = "10.55.0.2"

[eye_remote.pairing]
session_ttl = 300
qr_size = 256

[eye_remote.metrics]
refresh_interval = 2000
cache_ttl = 1000
```

### Eye Remote (`/etc/secubox-eye/config.toml`)

```toml
[gateway]
host = "10.55.0.1"
port = 8000
timeout = 5

[display]
width = 480
height = 480
refresh_ms = 2000

[auth]
token_file = "/etc/secubox-eye/device.token"
```

## USB OTG Gadget Modes

```bash
# Standard mode (network + serial)
sudo secubox-otg-gadget.sh start

# HID keyboard mode
sudo secubox-otg-gadget.sh tty

# Debug mode (network + storage)
sudo secubox-otg-gadget.sh debug

# Check status
sudo secubox-otg-gadget.sh status
```

## Troubleshooting

### Display Not Working

The HyperPixel 2.1 Round requires **legacy DPI mode** (not KMS):

```bash
# Check config.txt has these settings:
dtoverlay=hyperpixel2r
enable_dpi_lcd=1
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6

# NOT these (KMS doesn't work on Pi Zero W):
# dtoverlay=vc4-kms-v3d
# dtoverlay=vc4-kms-dpi-hyperpixel2r
```

### No Network Over USB

```bash
# On Eye Remote
ip addr show usb0
cat /var/log/usb0-up.log

# On SecuBox host
ip addr show | grep 10.55.0
```

### Services Status

```bash
ssh pi@10.55.0.2
systemctl status pigpiod
systemctl status hyperpixel2r-init
systemctl status lightdm
systemctl status nginx
systemctl status secubox-otg-gadget
```

## Security

- **JWT Authentication**: All API endpoints require valid JWT
- **Device Tokens**: SHA256 hashed, stored server-side
- **Pairing Sessions**: 5-minute TTL, single-use
- **Network Isolation**: OTG uses dedicated /30 subnet

## License

Proprietary - CyberMind / SecuBox
Author: Gérald Kerma <gandalf@gk2.net>
