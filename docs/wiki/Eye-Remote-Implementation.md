# Eye Remote v2.0.0 Implementation Guide

## Table of Contents

1. [Project Overview](#project-overview)
2. [Implementation Timeline](#implementation-timeline)
3. [Architecture Design](#architecture-design)
4. [Component Details](#component-details)
5. [Build System](#build-system)
6. [Display Configuration](#display-configuration)
7. [API Reference](#api-reference)
8. [Development Tools](#development-tools)
9. [Deployment](#deployment)
10. [Lessons Learned](#lessons-learned)

---

## Project Overview

### Purpose

SecuBox Eye Remote provides a dedicated physical display for SecuBox security appliances. The circular 480x480 LCD shows real-time system metrics, alerts, and status information.

### Goals Achieved

- [x] Offline-capable SD card image (no internet at boot)
- [x] USB OTG connectivity with fallback to WiFi
- [x] Secure device pairing via QR codes
- [x] Real-time metrics dashboard
- [x] Chromium kiosk mode auto-start
- [x] HyperPixel 2.1 Round display support
- [x] Gateway emulator for development

### Tech Stack

| Layer | Technology |
|-------|------------|
| OS | Raspberry Pi OS Bookworm (armhf) |
| Display | X11 + fbdev + DPI framebuffer |
| Window Manager | Openbox |
| Browser | Chromium (kiosk mode) |
| Backend | FastAPI + Uvicorn |
| Auth | JWT + Device Tokens |
| Build | QEMU ARM emulation |

---

## Implementation Timeline

### Task Breakdown (14 Tasks)

| Task | Component | Status |
|------|-----------|--------|
| 1 | Metrics Models (`models/metrics.py`) | ✅ |
| 2 | Device Models (`models/device.py`) | ✅ |
| 3 | Pairing Models (`models/pairing.py`) | ✅ |
| 4 | Metrics Collection (`core/metrics.py`) | ✅ |
| 5 | Device Registry (`core/device_registry.py`) | ✅ |
| 6 | Pairing Manager (`core/pairing.py`) | ✅ |
| 7 | Devices Router (`api/routers/devices.py`) | ✅ |
| 8 | Pairing Router (`api/routers/pairing.py`) | ✅ |
| 9 | Metrics Router (`api/routers/metrics.py`) | ✅ |
| 10 | Gateway Emulator (`tools/secubox-eye-gateway/`) | ✅ |
| 11 | Debian Packaging (`debian/`) | ✅ |
| 12 | Build Script Update | ✅ |
| 13 | Integration Tests | ✅ |
| 14 | HyperPixel Fix (Legacy DPI) | ✅ |

### Development Approach

Used **Subagent-Driven Development**:
1. Fresh subagent dispatched per task
2. Spec compliance review after implementation
3. Code quality review before completion
4. Two-stage review ensures correctness

---

## Architecture Design

### System Architecture

```
                                 SecuBox Appliance
                            ┌─────────────────────────┐
                            │                         │
                            │  ┌─────────────────┐   │
                            │  │ secubox-eye-    │   │
                            │  │ remote.service  │   │
                            │  │                 │   │
                            │  │ FastAPI:8000    │   │
                            │  └────────┬────────┘   │
                            │           │            │
                            │  ┌────────▼────────┐   │
                            │  │ USB Host        │   │
                            │  │ 10.55.0.1       │   │
                            │  └────────┬────────┘   │
                            │           │            │
                            └───────────┼────────────┘
                                        │ USB OTG
                                        │ (ECM + ACM)
                            ┌───────────┼────────────┐
                            │           │            │
                            │  ┌────────▼────────┐   │
                            │  │ USB Gadget      │   │
                            │  │ 10.55.0.2       │   │
                            │  └────────┬────────┘   │
                            │           │            │
                            │  ┌────────▼────────┐   │
                            │  │ nginx :8080     │   │
                            │  │ proxy → :8000   │   │
                            │  └────────┬────────┘   │
                            │           │            │
                            │  ┌────────▼────────┐   │
                            │  │ Chromium Kiosk  │   │
                            │  │ localhost:8080  │   │
                            │  └────────┬────────┘   │
                            │           │            │
                            │  ┌────────▼────────┐   │
                            │  │ HyperPixel      │   │
                            │  │ 480x480 LCD     │   │
                            │  └─────────────────┘   │
                            │                         │
                            │     RPi Zero W          │
                            └─────────────────────────┘
```

### Data Flow

```
┌──────────┐    GET /metrics    ┌──────────┐
│ Dashboard│◄──────────────────►│ FastAPI  │
│ (JS)     │    JSON response   │ Backend  │
└────┬─────┘                    └────┬─────┘
     │                               │
     │ fetch() every 2s              │ reads /proc/*
     │                               │ os.statvfs()
     ▼                               ▼
┌──────────┐                    ┌──────────┐
│ Canvas   │                    │ Linux    │
│ Rings    │                    │ Kernel   │
└──────────┘                    └──────────┘
```

---

## Component Details

### Models Layer

#### `models/metrics.py`
```python
class SystemMetrics(BaseModel):
    cpu_percent: float      # 0-100
    memory_percent: float   # 0-100
    disk_percent: float     # 0-100
    cpu_temp: float         # Celsius
    load_avg_1: float       # 1-minute load
    uptime_seconds: int
    hostname: str
    timestamp: datetime
```

#### `models/device.py`
```python
class Device(BaseModel):
    id: str                 # UUID
    name: str
    device_type: str        # "eye-remote"
    paired_at: datetime
    last_seen: datetime
    is_active: bool

class DeviceToken(BaseModel):
    device_id: str
    token_hash: str         # SHA256
    created_at: datetime
    expires_at: Optional[datetime]
```

#### `models/pairing.py`
```python
class PairingSession(BaseModel):
    session_id: str
    gateway_url: str
    expires_at: datetime
    qr_data: str            # JSON for QR code

class PairingRequest(BaseModel):
    session_id: str
    device_name: str
    device_type: str = "eye-remote"
```

### Core Layer

#### `core/metrics.py`
- Reads CPU from `/proc/stat` (delta calculation)
- Reads memory from `/proc/meminfo`
- Reads disk via `os.statvfs('/')`
- Reads temperature from `/sys/class/thermal/thermal_zone0/temp`
- Caches results for 1 second (async)

#### `core/device_registry.py`
- Stores devices in `/var/lib/secubox/eye-remote/devices.json`
- Token validation with `secrets.compare_digest()`
- SHA256 token hashing
- Thread-safe file operations

#### `core/pairing.py`
- 5-minute session TTL
- QR code contains: gateway URL, session ID, timestamp
- Single-use sessions (consumed on completion)

### API Layer

#### Authentication

```python
# JWT for management endpoints
async def require_jwt(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return payload

# Device token for metrics endpoint
async def require_device_token(x_device_token: str = Header(...)):
    device = registry.validate_token(x_device_token)
    return device
```

#### Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/devices/` | JWT | List paired devices |
| POST | `/devices/pair` | JWT | Pair new device |
| DELETE | `/devices/{id}` | JWT | Unpair device |
| POST | `/pairing/start` | JWT | Start pairing session |
| GET | `/pairing/qr/{session_id}` | JWT | Get QR code PNG |
| POST | `/pairing/complete` | None | Complete pairing (from device) |
| GET | `/metrics/` | Device Token | Get system metrics |

---

## Build System

### QEMU-Based Offline Build

The build script creates a complete SD card image with all packages pre-installed using QEMU ARM emulation:

```bash
┌─────────────────────────────────────────────────────┐
│                  Build Process                       │
├─────────────────────────────────────────────────────┤
│ 1. Decompress RPi OS Lite image                     │
│ 2. Expand image by 1GB for packages                 │
│ 3. Mount via loopback device                        │
│ 4. Copy qemu-arm-static for ARM emulation           │
│ 5. chroot and apt-get install packages              │
│ 6. Configure HyperPixel (legacy DPI mode)           │
│ 7. Install Eye Remote services                      │
│ 8. Configure kiosk (LightDM + Openbox + Chromium)   │
│ 9. Cleanup and create final image                   │
└─────────────────────────────────────────────────────┘
```

### Packages Pre-installed

```
chromium-browser    xserver-xorg         xinit
lightdm             openbox              unclutter
nginx               python3-pigpio       pigpio
i2c-tools           fonts-dejavu-core
```

---

## Display Configuration

### The HyperPixel Problem

**Issue:** Pi Zero W does not support KMS (Kernel Mode Setting) properly.

**Symptom:** Black screen with KMS overlays (`vc4-kms-v3d`, `vc4-kms-dpi-hyperpixel2r`).

**Solution:** Use legacy DPI mode with manual pixel timings.

### Working Configuration

```ini
# /boot/config.txt

# Legacy DPI overlay (NOT KMS)
dtoverlay=hyperpixel2r

# Manual DPI timings for ST7701S LCD
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
```

### ST7701S LCD Initialization

The HyperPixel 2.1 Round uses an ST7701S LCD controller that requires SPI initialization at boot:

```python
# /usr/bin/hyperpixel2r-init (simplified)
import pigpio

pi = pigpio.pi()
# Bit-bang SPI commands to ST7701S
# Initialize display registers
# Enable backlight
pi.stop()
```

### Service Dependencies

```
pigpiod.service
    └── hyperpixel2r-init.service
            └── lightdm.service
                    └── chromium (kiosk)
```

---

## API Reference

### GET /api/v1/eye-remote/metrics/

**Auth:** `X-Device-Token` header

**Response:**
```json
{
  "cpu_percent": 23.5,
  "memory_percent": 45.2,
  "disk_percent": 28.0,
  "cpu_temp": 48.3,
  "load_avg_1": 0.42,
  "uptime_seconds": 86400,
  "hostname": "secubox-pro",
  "timestamp": "2026-04-21T20:30:00Z"
}
```

### POST /api/v1/eye-remote/pairing/start

**Auth:** JWT Bearer token

**Response:**
```json
{
  "session_id": "abc123",
  "expires_at": "2026-04-21T20:35:00Z",
  "qr_url": "/api/v1/eye-remote/pairing/qr/abc123"
}
```

### POST /api/v1/eye-remote/pairing/complete

**Auth:** None (uses session_id)

**Request:**
```json
{
  "session_id": "abc123",
  "device_name": "Living Room Eye",
  "device_type": "eye-remote"
}
```

**Response:**
```json
{
  "device_id": "dev_xyz789",
  "token": "raw_token_for_device_storage",
  "gateway_url": "http://10.55.0.1:8000"
}
```

---

## Development Tools

### Gateway Emulator

Simulates SecuBox metrics without physical hardware:

```bash
# Install
pip install -e tools/secubox-eye-gateway/

# Run with profile
secubox-eye-gateway --profile stressed --port 8765

# Profiles:
#   idle     - Low activity (CPU ~5%, temp ~40°C)
#   normal   - Typical load (CPU ~25%, temp ~50°C)
#   busy     - Heavy load (CPU ~65%, temp ~62°C)
#   stressed - Near limits (CPU ~85%, temp ~72°C)
```

### Emulator Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/health` | Health check |
| `GET /api/v1/system/metrics` | Simulated metrics |
| `GET /api/v1/eye-remote/discover` | Discovery info |

---

## Deployment

### SD Card Flashing

```bash
# Build image
sudo ./remote-ui/round/build-eye-remote-image.sh \
    -i raspios-lite-armhf.img.xz \
    -s "WiFiSSID" -p "password"

# Flash
sudo dd if=/tmp/secubox-eye-remote-2.0.0.img \
    of=/dev/sdX bs=4M status=progress

# Or compressed
xz -9 /tmp/secubox-eye-remote-2.0.0.img
xzcat *.img.xz | sudo dd of=/dev/sdX bs=4M status=progress
```

### First Boot Checklist

- [ ] Insert SD card
- [ ] Connect USB DATA port (middle) to SecuBox
- [ ] Wait 60 seconds
- [ ] Display shows dashboard
- [ ] SSH accessible: `ssh pi@10.55.0.2`

### OTA Updates

```bash
# Update dashboard
scp index.html pi@10.55.0.2:/var/www/secubox-round/

# Update backend (on SecuBox host)
apt update && apt install secubox-eye-remote

# Restart services
systemctl restart secubox-eye-remote
```

---

## Lessons Learned

### 1. KMS vs Legacy DPI

**Problem:** Assumed KMS would work everywhere since it's the "modern" approach.

**Reality:** Pi Zero W (BCM2835) has limited GPU support. KMS overlays cause black screen.

**Solution:** Always test on actual hardware. Use legacy DPI mode for Pi Zero W.

### 2. ST7701S Initialization

**Problem:** Display stayed black even with correct overlay.

**Reality:** ST7701S LCD controller requires SPI commands at boot.

**Solution:** `hyperpixel2r-init` script using pigpio for GPIO/SPI access.

### 3. QEMU Package Installation

**Problem:** Pi Zero W is slow. Installing packages at first boot takes forever.

**Reality:** ARM emulation via QEMU allows pre-installing packages during image build.

**Solution:** QEMU chroot in build script. Offline-capable images.

### 4. Token Security

**Problem:** Device tokens stored in plain text.

**Reality:** Compromised token = unauthorized access.

**Solution:** SHA256 hash stored server-side. `secrets.compare_digest()` for timing-safe comparison.

---

## References

- [Pimoroni HyperPixel 2.1 Round](https://github.com/pimoroni/hyperpixel2r)
- [Raspberry Pi DPI Display](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#parallel-display-interface-dpi)
- [pigpio Library](http://abyz.me.uk/rpi/pigpio/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

*CyberMind · SecuBox Eye Remote v2.0.0 · April 2026*
