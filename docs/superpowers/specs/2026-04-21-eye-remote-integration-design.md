# Eye Remote Integration — Design Specification

**Date:** 2026-04-21
**Author:** Claude + Gérald Kerma
**Status:** Approved
**Version:** 1.0.0

---

## 1. Overview

This specification defines the integration between SecuBox Eye Remote (HyperPixel 2.1 Round display on Pi Zero W) and SecuBox appliances (ESPRESSObin/MOCHAbin). The system enables:

- **Real-time metrics display** from SecuBox on Eye Remote
- **Bidirectional control** — Eye Remote can control SecuBox services
- **Multi-SecuBox support** — One Eye Remote connects to multiple SecuBoxes
- **Full management WebUI** on SecuBox for Eye Remote administration
- **Development gateway/emulator** for local testing

### Topology

```
                    ┌─────────────────┐
                    │   Eye Remote    │  ← ONE display device
                    │  (HyperPixel)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │  SecuBox #1  │ │  SecuBox #2  │ │  SecuBox #3  │
      │ (ESPRESSObin)│ │  (MOCHAbin)  │ │  (Virtual)   │
      └──────────────┘ └──────────────┘ └──────────────┘
```

---

## 2. Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `secubox-eye-agent` | Eye Remote (Pi Zero W) | Network, auth, commands, multi-SecuBox management |
| `fb_dashboard.py` | Eye Remote | Framebuffer display rendering |
| `secubox-eye-remote` | SecuBox | Management API + WebUI module |
| `secubox-eye-gateway` | Dev machine / Server | Emulator + multi-SecuBox gateway |

---

## 3. Eye Remote Agent Architecture

### 3.1 Component Diagram

```
Eye Remote (Pi Zero W)
┌─────────────────────────────────────────────────────────┐
│  secubox-eye-agent.service                              │
│  ├── DeviceManager      ← Manages connections to N SecuBoxes
│  │   ├── SecuBox #1 (active) ──► metrics stream
│  │   ├── SecuBox #2 (standby)
│  │   └── SecuBox #3 (standby)
│  ├── MetricsBridge      ← Feeds current metrics to dashboard
│  ├── CommandHandler     ← WebSocket commands (reboot, screenshot...)
│  └── ConfigStore        ← /etc/secubox-eye/config.toml
├─────────────────────────────────────────────────────────┤
│  secubox-fb-dashboard.service                           │
│  ├── Reads metrics from agent via Unix socket           │
│  ├── Shows active SecuBox name in center                │
│  └── Touch: swipe left/right to switch SecuBox          │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Configuration File

**Location:** `/etc/secubox-eye/config.toml`

```toml
[device]
id = "eye-remote-001"
name = "Dashboard Principale"

[[secubox]]
name = "Home Lab"
host = "10.55.0.1"           # OTG primary
fallback = "secubox.local"   # WiFi fallback
token = "device-token-abc123"
active = true

[[secubox]]
name = "Office"
host = "192.168.1.100"
token = "device-token-def456"
active = false

[[secubox]]
name = "Production"
host = "prod.secubox.in"
token = "device-token-ghi789"
active = false
```

### 3.3 File Structure

```
/etc/secubox-eye/
├── config.toml              # Device config + SecuBox list
├── device.key               # ED25519 private key
└── device.pub               # Public key (shared during pairing)

/usr/local/bin/
├── secubox-eye-agent        # Main agent (Python)
└── fb_dashboard.py          # Display renderer

/usr/lib/secubox-eye/
├── agent/
│   ├── __init__.py
│   ├── main.py              # Entry point
│   ├── device_manager.py    # Multi-SecuBox connections
│   ├── metrics_bridge.py    # Shares metrics with dashboard
│   ├── command_handler.py   # WebSocket command processing
│   ├── pairing.py           # Pairing flow + QR generation
│   ├── ssh_manager.py       # Auto SSH key provisioning
│   └── ota_updater.py       # Self-update capability
└── dashboard/
    ├── fb_dashboard.py      # Enhanced (reads from agent)
    └── touch_handler.py     # Gesture recognition for control

/run/secubox-eye/
├── metrics.sock             # Unix socket: agent → dashboard
├── agent.pid
└── current_secubox.json     # Active SecuBox info

/etc/systemd/system/
├── secubox-eye-agent.service
└── secubox-fb-dashboard.service
```

### 3.4 Metrics Bridge Protocol

Unix socket at `/run/secubox-eye/metrics.sock`:

```json
{
  "secubox": {
    "name": "Home Lab",
    "host": "10.55.0.1",
    "transport": "otg"
  },
  "metrics": {
    "cpu_percent": 34.5,
    "mem_percent": 67.2,
    "disk_percent": 45.0,
    "wifi_rssi": -55,
    "load_avg_1": 0.82,
    "cpu_temp": 52.3,
    "uptime_seconds": 86400,
    "hostname": "secubox-lab",
    "modules_active": ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]
  },
  "alerts": {
    "global_level": "nominal",
    "items": []
  },
  "timestamp": "2026-04-21T14:32:07Z"
}
```

---

## 4. Authentication

### 4.1 Device Token Authentication

Eye Remote uses pre-shared device tokens for automatic authentication without user interaction.

**Token structure:**
```json
{
  "device_id": "eye-remote-001",
  "secubox_id": "secubox-lab-001",
  "scopes": [
    "metrics:read",
    "services:restart",
    "otg:control",
    "alerts:dismiss",
    "system:lockdown"
  ],
  "ssh_enabled": true,
  "ssh_auto": true,
  "issued_at": "2026-04-21T10:30:00Z",
  "expires_at": null
}
```

**Token storage on SecuBox:** `/var/lib/secubox/eye-remote/devices.json`

```json
{
  "eye-remote-001": {
    "name": "Dashboard Principale",
    "token_hash": "sha256:abc123...",
    "paired_at": "2026-04-21T10:30:00Z",
    "last_seen": "2026-04-21T14:32:07Z",
    "transport": "otg",
    "firmware": "1.11.0",
    "capabilities": ["screenshot", "reboot", "ota"],
    "scopes": ["metrics:read", "services:restart", "otg:control"],
    "ssh_pubkey": "ssh-ed25519 AAAA..."
  }
}
```

### 4.2 Future: User Profile Integration

When Eye Remote is paired, it can optionally be linked to a SecuBox user account. The Eye Remote inherits that user's permissions:

- **Admin Eye Remote** → full control
- **User Eye Remote** → view-only metrics, limited actions
- **Operator Eye Remote** → restart services, dismiss alerts

---

## 5. Pairing Flow

### 5.1 Touchless Pairing (Eye Remote initiates)

```
Eye Remote                              SecuBox
    │                                      │
    │  ← User scans QR on Eye screen       │
    │    (QR shows: secubox://10.55.0.1)   │
    │                                      │
    ├──GET /api/v1/eye-remote/discover────►│
    │◄─────── {name, version, pubkey} ─────┤
    │                                      │
    ├──POST /api/v1/eye-remote/pair ──────►│
    │  {device_id, pubkey, capabilities}   │
    │◄─────── {token, ssh_port, config} ───┤
    │                                      │
    │  [Eye stores token + SSH key]        │
    │                                      │
    ├──WS /api/v1/eye-remote/ws ──────────►│
    │◄════════ Connected ═════════════════►│
```

### 5.2 Eye Remote Pairing Screen

```
┌────────────────────────────────────────┐
│         ● SECUBOX EYE REMOTE           │
│           PAIRING MODE                  │
│                                         │
│         ┌─────────────────┐             │
│         │ ▄▄▄▀▀▀▄▄▄▀▀▀▄▄▄ │             │
│         │ █▀█▄▄▄█▀█▄▄▄█▀█ │  ← QR      │
│         │ ▀▀▀█▀█▀▀▀█▀█▀▀▀ │             │
│         └─────────────────┘             │
│                                         │
│    Scan with SecuBox mobile app         │
│    or visit: eye.local:8080/pair        │
│                                         │
│         [ Manual Setup ]                │
└────────────────────────────────────────┘
```

### 5.3 QR Code Content

The QR code encodes a URL:
```
secubox://10.55.0.1/pair?device=eye-remote-001&pubkey=ssh-ed25519...
```

Alternative for manual entry:
- **Host:** `10.55.0.1` or `secubox.local`
- **Code:** `A7X-K9M` (6-char alphanumeric, expires in 5 minutes)

### 5.4 SSH Auto-Provisioning

During pairing, Eye Remote sends its ED25519 public key. SecuBox:

1. Creates dedicated user `eye-001` (or uses existing)
2. Adds public key to `~eye-001/.ssh/authorized_keys`
3. Returns SSH connection details

Eye Remote can then SSH without password for:
- OTA updates
- Direct command execution
- Emergency recovery

---

## 6. Communication Model

### 6.1 Hybrid: Pull + WebSocket

| Channel | Direction | Purpose | Interval |
|---------|-----------|---------|----------|
| HTTP GET | Eye → SecuBox | Metrics polling | 2 seconds |
| WebSocket | Bidirectional | Commands, events | Persistent |

### 6.2 Metrics Polling

```
GET /api/v1/eye-remote/metrics
Authorization: Bearer <device-token>

Response:
{
  "cpu_percent": 34.5,
  "mem_percent": 67.2,
  "disk_percent": 45.0,
  "wifi_rssi": -55,
  "load_avg_1": 0.82,
  "cpu_temp": 52.3,
  "uptime_seconds": 86400,
  "hostname": "secubox-lab",
  "secubox_version": "2.0.0",
  "modules_active": ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]
}
```

### 6.3 WebSocket Commands

**Endpoint:** `WS /api/v1/eye-remote/ws/{device_id}`

**SecuBox → Eye Remote:**
```json
{"type": "command", "cmd": "screenshot", "request_id": "abc123"}
{"type": "command", "cmd": "reboot", "delay": 5}
{"type": "command", "cmd": "config_update", "config": {...}}
{"type": "command", "cmd": "ota_update", "url": "https://..."}
```

**Eye Remote → SecuBox:**
```json
{"type": "response", "request_id": "abc123", "data": {"image": "base64..."}}
{"type": "event", "event": "touch", "action": "service_restart", "target": "AUTH"}
{"type": "heartbeat", "uptime": 3600}
```

---

## 7. Eye Remote as Controller

### 7.1 Control Capabilities

| Action | Touch Gesture | API Call |
|--------|---------------|----------|
| Switch OTG mode | Long-press MESH pod | `POST /system/otg/mode` |
| Restart service | Long-press module pod | `POST /system/service_control` |
| Block threat | Tap alert notification | `POST /crowdsec/decisions` |
| Toggle WiFi AP | Swipe down from top | `POST /netmodes/toggle` |
| Emergency lockdown | 3-finger tap | `POST /system/lockdown` |
| Switch SecuBox | Swipe left/right | Local (agent) |

### 7.2 Control Permissions

Defined in device token `scopes`:

| Scope | Allows |
|-------|--------|
| `metrics:read` | Read system metrics (default) |
| `services:restart` | Restart SecuBox services |
| `otg:control` | Switch OTG/network modes |
| `alerts:dismiss` | Dismiss/acknowledge alerts |
| `system:lockdown` | Emergency lockdown mode |
| `system:reboot` | Reboot SecuBox |

---

## 8. SecuBox Module (`secubox-eye-remote`)

### 8.1 API Endpoints

```
/api/v1/eye-remote/
├── GET    /status                    # Module status
├── GET    /devices                   # List paired devices
├── GET    /devices/{id}              # Get device details
├── DELETE /devices/{id}              # Unpair device
├── POST   /pair                      # Initiate pairing
├── GET    /pair/qr                   # Generate pairing QR
├── POST   /pair/complete             # Complete pairing (from Eye)
├── GET    /metrics                   # Metrics for Eye (with auth)
├── POST   /command/{device_id}       # Send command to Eye
│          ├── screenshot
│          ├── reboot
│          ├── config_update
│          └── ota_update
├── WS     /ws/{device_id}            # WebSocket for Eye
├── WS     /serial                    # Serial console passthrough
└── GET    /discover                  # Discovery endpoint (no auth)
```

### 8.2 File Structure

```
packages/secubox-eye-remote/
├── api/
│   ├── main.py              # FastAPI app
│   └── routers/
│       ├── devices.py       # Device registry CRUD
│       ├── pairing.py       # Pairing endpoints
│       ├── commands.py      # Command dispatch
│       ├── serial.py        # Serial console bridge
│       └── websocket.py     # WS endpoint for Eye Remote
├── core/
│   ├── device_registry.py   # Paired devices storage
│   ├── token_manager.py     # Device token generation/validation
│   ├── serial_bridge.py     # Async serial ↔ WebSocket
│   └── screenshot.py        # Screenshot handling
├── www/
│   ├── index.html           # Management dashboard
│   ├── pairing.html         # Pairing page with QR
│   ├── terminal.html        # xterm.js serial console
│   ├── css/eye-remote.css
│   └── js/
│       ├── eye-remote.js    # Main UI logic
│       ├── terminal.js      # xterm.js integration
│       └── qrcode.min.js    # QR generation
├── debian/
│   ├── control
│   ├── postinst
│   └── rules
├── nginx/
│   └── eye-remote.conf
└── menu.d/
    └── 50-eye-remote.json   # Hub menu integration
```

### 8.3 WebUI Mockup

```
┌─────────────────────────────────────────────────────────────┐
│  ≡ SecuBox    [System ▾]  [Security ▾]  [Eye Remote]  👤    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  EYE REMOTE MANAGEMENT                                      │
│  ═══════════════════════════════════════════════════════   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  📱 eye-remote-001            ● Connected (OTG)     │   │
│  │  ├─ Firmware: v1.11.0                               │   │
│  │  ├─ Uptime: 2h 34m                                  │   │
│  │  ├─ Last metrics: 2s ago                            │   │
│  │  └─ IP: 10.55.0.2                                   │   │
│  │                                                     │   │
│  │  [📷 Screenshot] [🔄 Reboot] [⬆️ Update] [⚙️ Config]│   │
│  │  [🖥️ Serial Console]  [❌ Unpair]                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CONFIGURATION                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Display refresh:  [2s ▾]                           │   │
│  │  Active SecuBox:   [This device ▾]                  │   │
│  │  Alert thresholds: [Use SecuBox defaults ▾]         │   │
│  │  Control enabled:  [✓] Allow service restart        │   │
│  │                    [✓] Allow OTG mode switch        │   │
│  │                    [ ] Allow system lockdown        │   │
│  │                                                     │   │
│  │  SSH Access:       [✓] Enabled (auto-key)           │   │
│  │                                                     │   │
│  │              [Save Configuration]                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PAIR NEW DEVICE                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │       ┌─────────────┐                               │   │
│  │       │ ▄▄▄ ▀▀▀ ▄▄▄ │  Scan this QR from Eye Remote │   │
│  │       │ █▀█ ▄▄▄ █▀█ │  or enter manually:           │   │
│  │       │ ▀▀▀ █▀█ ▀▀▀ │                               │   │
│  │       └─────────────┘  secubox://10.55.0.1/pair     │   │
│  │                        Code: A7X-K9M                │   │
│  │                                                     │   │
│  │  Pairing expires in: 4:32                           │   │
│  │              [Generate New Code]                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  SERIAL CONSOLE  (click to expand)                     [▾] │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  $ _                                                │   │
│  │  (xterm.js terminal - /dev/ttyACM0 @ 115200)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Gateway/Emulator Tool

### 9.1 Overview

`secubox-eye-gateway` is a development and fleet management tool that can:

1. **Emulate** SecuBox API for local testing
2. **Proxy** requests to real SecuBox hardware
3. **Aggregate** multiple SecuBoxes for fleet view

### 9.2 CLI Interface

```bash
# Pure emulator (no real hardware)
secubox-eye-gateway --emulate --port 8000

# Gateway to single real SecuBox
secubox-eye-gateway --gateway --target 192.168.1.50

# Multi-SecuBox gateway
secubox-eye-gateway --gateway --config /etc/secubox-eye-gateway/fleet.toml

# Hybrid: emulate "Lab" + proxy to real "Production"
secubox-eye-gateway --hybrid \
  --emulate-name "Lab" \
  --target prod=192.168.1.50 \
  --target office=10.0.0.100
```

### 9.3 Fleet Configuration

**Location:** `/etc/secubox-eye-gateway/fleet.toml`

```toml
[gateway]
listen = "0.0.0.0:8000"
eye_remote_token = "shared-or-per-device"

[[secubox]]
name = "Production"
host = "192.168.1.50"
ssh_user = "secubox"
ssh_key = "~/.ssh/secubox_prod"
priority = 1  # Primary

[[secubox]]
name = "Office"
host = "10.0.0.100"
priority = 2

[[secubox]]
name = "Lab (Emulated)"
emulate = true
metrics_profile = "busy"  # idle, normal, busy, stressed
```

### 9.4 Emulation Profiles

```python
PROFILES = {
    "idle": {
        "cpu": (5, 15),      # range for random drift
        "mem": (20, 35),
        "temp": (38, 45),
        "alerts": []
    },
    "normal": {
        "cpu": (20, 45),
        "mem": (40, 60),
        "temp": (45, 55),
        "alerts": ["warn:cpu occasional spike"]
    },
    "busy": {
        "cpu": (60, 85),
        "mem": (70, 85),
        "temp": (55, 68),
        "alerts": ["warn:mem", "warn:cpu"]
    },
    "stressed": {
        "cpu": (85, 99),
        "mem": (90, 98),
        "temp": (70, 82),
        "alerts": ["crit:cpu", "crit:mem", "warn:temp"]
    }
}
```

### 9.5 Fleet API

```
GET /api/v1/fleet/summary
{
  "secuboxes": [
    {"name": "Production", "status": "ok", "cpu": 34, "alerts": 0},
    {"name": "Office", "status": "warn", "cpu": 78, "alerts": 2},
    {"name": "Lab", "status": "ok", "cpu": 12, "alerts": 0, "emulated": true}
  ],
  "active": "Production",
  "total_alerts": 2
}

GET /api/v1/fleet/{name}/metrics   # Full metrics for specific SecuBox
POST /api/v1/fleet/{name}/command  # Route command to specific SecuBox
POST /api/v1/fleet/switch          # Switch active SecuBox
```

### 9.6 File Structure

```
tools/secubox-eye-gateway/
├── gateway/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── server.py            # FastAPI app
│   ├── emulator.py          # Fake metrics generator
│   ├── proxy.py             # Proxy to real SecuBox
│   ├── fleet.py             # Multi-SecuBox aggregation
│   └── profiles.py          # Emulation profiles
├── fleet.toml.example
├── requirements.txt
├── setup.py
└── README.md
```

---

## 10. Screenshot Capture Flow

```
WebUI                    SecuBox API                Eye Remote
  │                          │                          │
  ├─POST /eye-remote/command─►│                          │
  │  {cmd: "screenshot"}     │                          │
  │                          ├──WS: screenshot_request──►│
  │                          │                          │
  │                          │  [PIL captures fb0]      │
  │                          │                          │
  │                          │◄──WS: screenshot_data────┤
  │                          │   (base64 PNG, ~200KB)   │
  │◄─────── {image: "..."}───┤                          │
  │                          │                          │
  │  [Display in modal]      │                          │
```

---

## 11. OTA Update Flow

```
SecuBox                     Eye Remote
    │                          │
    ├──WS: ota_update──────────►│
    │  {url, version, hash}    │
    │                          │
    │  [Download to /tmp]      │
    │  [Verify SHA256]         │
    │  [Extract to staging]    │
    │                          │
    │◄──WS: ota_progress───────┤
    │  {stage: "downloading", pct: 45}
    │                          │
    │  [Swap /usr/lib/secubox-eye]
    │  [Restart services]      │
    │                          │
    │◄──WS: ota_complete───────┤
    │  {version: "1.12.0"}     │
```

---

## 12. Dependencies

### Eye Remote (Pi Zero W)

```
python3-pigpio          # GPIO for LCD init
python3-pil             # Framebuffer rendering
python3-websockets      # WebSocket client
python3-aiohttp         # Async HTTP client
python3-toml            # Config parsing
python3-qrcode          # QR code generation
python3-paramiko        # SSH key management (optional)
```

### SecuBox Module

```
python3-fastapi
python3-uvicorn
python3-websockets
python3-pyserial        # Serial console bridge
python3-qrcode
python3-pydantic
```

### Gateway Tool

```
fastapi
uvicorn
httpx                   # Async HTTP client for proxying
websockets
toml
click                   # CLI framework
```

---

## 13. Security Considerations

1. **Device tokens** are SHA256-hashed before storage on SecuBox
2. **SSH keys** are ED25519 (not RSA) for smaller size and better security
3. **WebSocket** connections require valid device token
4. **Pairing codes** expire after 5 minutes
5. **Control actions** require explicit scope in device token
6. **Serial console** access logged to audit trail
7. **OTA updates** require SHA256 verification before install

---

## 14. Future Enhancements

1. **User profile integration** — Eye Remote permissions linked to SecuBox user accounts
2. **Multi-Eye fleet** — One SecuBox managing multiple Eye Remote devices
3. **Encrypted metrics** — TLS for all Eye ↔ SecuBox communication
4. **Offline caching** — Eye stores last N minutes of metrics for display during disconnection
5. **Alert sounds** — Piezo buzzer on Eye Remote for critical alerts

---

## 15. Implementation Order

1. **Phase 1: Eye Remote Agent** — Basic metrics fetch from single SecuBox
2. **Phase 2: SecuBox Module** — API + device registry + pairing
3. **Phase 3: WebUI** — Management dashboard on SecuBox
4. **Phase 4: Control** — Bidirectional commands via WebSocket
5. **Phase 5: Multi-SecuBox** — Device manager for multiple SecuBoxes
6. **Phase 6: Gateway** — Emulator and fleet management tool
7. **Phase 7: Polish** — OTA, serial console, screenshot

---

*SecuBox Eye Remote Integration — Design Specification v1.0.0*
*CyberMind — https://cybermind.fr*
