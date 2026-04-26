# Eye Remote Swiss Army Dashboard — Design Specification

**Date:** 2026-04-26
**Author:** Claude + Gérald Kerma
**Status:** Approved
**Target:** Pi Zero W + HyperPixel 2.1 Round (480x480)

---

## 1. Overview

Transform Eye Remote from a simple metrics display into a **Swiss Army multi-tool** with 4 operating modes, touchless web-based control, and intelligent failover.

### Goals
- Multi-mode operation: Dashboard / Local / Flash / Gateway
- Touchless control via Web Remote (no working touchscreen)
- Plug-and-play with smart auto-detection and flag file overrides
- Graceful failover with visual feedback
- Full system control: WiFi, Bluetooth, Display, SecuBox management

### Non-Goals
- Touch input (disabled due to defective ft5x06 hardware)
- Bluetooth keyboard support (deferred to future version)
- Phone app development

---

## 2. Operating Modes

### 2.1 Mode Overview

| Mode | Trigger | Display | Purpose |
|------|---------|---------|---------|
| **Dashboard** | SecuBox API responds (auto) | 6 metric rings, real-time data | Primary monitoring |
| **Local** | No API / fallback after 60s | Pi Zero stats + icon grid | Standalone operation |
| **Flash** | `/FORCE_FLASH` flag file | USB storage + progress + U-Boot | ESPRESSObin recovery |
| **Gateway** | `/FORCE_GATEWAY` flag file | Multi-SecuBox fleet view | Fleet management |

### 2.2 Mode Switching Logic

```
Boot
  │
  ├─► Check /FORCE_FLASH on USB storage ──► Flash Mode
  │
  ├─► Check /FORCE_GATEWAY on USB storage ──► Gateway Mode
  │
  └─► Auto-detect:
        │
        ├─► SecuBox API responds (OTG/WiFi) ──► Dashboard Mode
        │
        └─► API timeout (3s) ──► Local Mode
```

### 2.3 Flag File Locations

Flag files reside on the USB mass storage partition (FAT32):
- `/FORCE_FLASH` — Force Flash mode on boot
- `/FORCE_GATEWAY` — Force Gateway mode on boot
- No flag = auto-detect (Dashboard if API, else Local)

---

## 3. Failover Behavior

### 3.1 API Disconnection (Dashboard → Local)

Staged transition with visual feedback:

| Time | Display State |
|------|---------------|
| 0s | Stale data + pulsing "OFFLINE" badge |
| 15s | Metric rings fade to gray, time/hostname remain |
| 60s | Full transition to Local mode |

Auto-reconnect attempts every 10s in background. Silent recovery when API returns.

### 3.2 USB Cable Replug

1. Display "Connecting..." spinner during USB re-enumeration
2. Green flash animation on successful reconnection
3. Resume previous mode automatically

---

## 4. Architecture

### 4.1 Unified Python Agent

Single process architecture for Pi Zero's limited resources (512MB RAM):

```
┌─────────────────────────────────────────────────────────┐
│                   eye-agent (Python)                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ Mode Manager│  │  Failover   │  │  Display    │     │
│  │ (state machine)│ (connection) │  │ (framebuffer)│    │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Web Server │  │   System    │  │  SecuBox    │     │
│  │  (FastAPI)  │  │  Controls   │  │   Client    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
```

### 4.2 File Structure

```
remote-ui/round/
├── agent/
│   ├── main.py                 # Entry point, async event loop
│   ├── config.py               # Settings from TOML + flag files
│   ├── mode_manager.py         # NEW: State machine for 4 modes
│   ├── failover.py             # NEW: Connection monitoring + transitions
│   ├── display/
│   │   ├── renderer.py         # Framebuffer rendering (from fb_dashboard.py)
│   │   ├── mode_dashboard.py   # Dashboard mode display
│   │   ├── mode_local.py       # Local mode display
│   │   ├── mode_flash.py       # Flash mode display
│   │   └── mode_gateway.py     # Gateway mode display
│   ├── web/
│   │   ├── server.py           # NEW: FastAPI app for Web Remote
│   │   ├── routes/
│   │   │   ├── mode.py         # Mode switching endpoints
│   │   │   ├── wifi.py         # WiFi configuration
│   │   │   ├── bluetooth.py    # Bluetooth management
│   │   │   ├── display.py      # Display settings
│   │   │   ├── devices.py      # SecuBox device manager
│   │   │   ├── system.py       # System actions
│   │   │   └── secubox.py      # SecuBox remote control
│   │   └── static/
│   │       └── control.html    # Web Remote UI (single page)
│   ├── system/
│   │   ├── wifi_manager.py     # NEW: nmcli wrapper
│   │   ├── bt_manager.py       # NEW: bluetoothctl wrapper
│   │   └── display_ctl.py      # NEW: brightness, timeout
│   └── secubox_client.py       # Existing: API client
├── files/
│   └── etc/secubox/eye-remote/
│       ├── gadget-setup.sh     # Existing
│       └── eye-remote.toml     # NEW: Unified config
└── secubox-eye-agent.service   # Systemd unit (updated)
```

---

## 5. Display Designs

### 5.1 Dashboard Mode (480x480)

```
         ● OTG CONNECTED
    ╭─────────────────────────╮
   ╱  ╭───────────────────╮    ╲
  │  ╱  ╭───────────────╮  ╲    │
  │ │  ╱  ╭───────────╮  ╲  │   │   6 concentric
  │ │ │  ╱           ╲  │  │   │   metric rings
  │ │ │ │   14:32:07  │ │  │   │   (AUTH/WALL/BOOT/
  │ │ │ │ secubox-zro │ │  │   │    MIND/ROOT/MESH)
  │ │ │  ╲  ● NOMINAL╱  │  │   │
  │ │  ╲  ╰───────────╯  ╱  │   │
  │  ╲  ╰───────────────╯  ╱    │
   ╲  ╰───────────────────╯    ╱
    ╰─────────────────────────╯
```

Elements:
- 6 neon-colored metric rings (CPU/MEM/DISK/LOAD/TEMP/WIFI)
- Center: Time (HH:MM:SS), hostname, uptime
- Top badge: Connection type (OTG/WiFi/SIM)
- Bottom: Status indicator (NOMINAL/WARNING/CRITICAL)

### 5.2 Local Mode

```
           ● LOCAL MODE
    ╭─────────────────────────╮
   ╱                           ╲
  │     📡    🔋    💾          │   Icon grid:
  │                             │   - Network status
  │     📶    ⚙️    🔄          │   - Battery/Power
  │                             │   - Storage
  │    Pi Zero W • up 2h15m     │   - WiFi signal
  │                             │   - Settings
   ╲  Web: eye-remote.local:8080 ╱   - Refresh
    ╰─────────────────────────╯
```

### 5.3 Flash Mode

```
          ⚡ FLASH MODE
    ╭─────────────────────────╮
   ╱                           ╲
  │           💾               │
  │      USB STORAGE           │
  │     2.0 GB • FAT32         │
  │                             │
  │    ████████████░░░░ 75%    │   Progress bar
  │      Flashing image...      │
  │                             │
   ╲      U-Boot ready         ╱
    ╰─────────────────────────╯
```

### 5.4 Gateway Mode

```
          🌐 GATEWAY MODE
    ╭─────────────────────────╮
   ╱                           ╲
  │          🖥️                │
  │                             │
  │   ● secubox-main           │   Fleet status list
  │   ● secubox-lab            │   with connection
  │   ○ secubox-remote (down)  │   indicators
  │   ● secubox-backup         │
  │                             │
  │      Fleet: 3/4 online     │
   ╲        ▲ 1 alert          ╱
    ╰─────────────────────────╯
```

---

## 6. Web Remote Control

### 6.1 Access

- **URL:** `http://eye-remote.local:8080/control`
- **Port:** 8080 (embedded FastAPI server)
- **Access methods:**
  - Same WiFi network
  - USB OTG (10.55.0.2:8080 from connected host)

### 6.2 Features

| Feature | Description |
|---------|-------------|
| **Mode Switching** | Buttons to switch Dashboard/Local/Flash/Gateway |
| **WiFi Configuration** | Scan networks, connect, show signal strength |
| **Bluetooth Management** | Enable/disable, scan, pair devices |
| **Display Settings** | Brightness (0-100), screen timeout, theme |
| **SecuBox Device Manager** | Add/remove SecuBoxes, set primary, mDNS discovery |
| **System Actions** | Reboot, shutdown, view logs, export diagnostics |
| **SecuBox Remote Control** | Restart services, trigger lockdown, view logs |

### 6.3 API Endpoints

```
GET  /api/mode                    # Current mode
POST /api/mode                    # Set mode {mode: "dashboard"|"local"|"flash"|"gateway"}

GET  /api/wifi/status             # Current WiFi status
GET  /api/wifi/scan               # Scan available networks
POST /api/wifi/connect            # Connect {ssid, password}

GET  /api/bluetooth/status        # BT enabled/disabled
POST /api/bluetooth/enable        # Enable Bluetooth
GET  /api/bluetooth/devices       # List paired/available
POST /api/bluetooth/pair          # Pair device {address}

GET  /api/display/settings        # Current settings
POST /api/display/brightness      # Set brightness {value: 0-100}
POST /api/display/timeout         # Set timeout {seconds}

GET  /api/devices                 # List SecuBox devices
POST /api/devices                 # Add device {name, host, port}
DELETE /api/devices/{id}          # Remove device

POST /api/system/reboot           # Reboot Eye Remote
POST /api/system/shutdown         # Shutdown Eye Remote
GET  /api/system/logs             # Recent logs

GET  /api/secubox/{id}/status     # SecuBox status
POST /api/secubox/{id}/restart    # Restart SecuBox service
POST /api/secubox/{id}/lockdown   # Trigger lockdown mode
```

### 6.4 UI Design Principles

- **Mobile-first:** 360px base width, touch-friendly (44px min tap targets)
- **Dark theme:** Matches HyperPixel display aesthetic (#0a0a0f background)
- **Single page:** All features visible, no navigation required
- **Real-time:** WebSocket updates for status changes
- **Offline-capable:** Service worker caches UI

---

## 7. Configuration

### 7.1 Config File: `/etc/secubox/eye-remote/eye-remote.toml`

```toml
[device]
id = "eye-remote-001"
name = "Eye Remote Living Room"

[display]
brightness = 80
timeout_seconds = 300
theme = "neon"  # neon | classic | minimal

[mode]
default = "auto"  # auto | dashboard | local | flash | gateway
auto_fallback_seconds = 60
reconnect_interval_seconds = 10

[web]
enabled = true
port = 8080
bind = "0.0.0.0"

[secuboxes]
primary = "secubox-main"

[[secuboxes.devices]]
id = "secubox-main"
name = "SecuBox Main"
host = "10.55.0.1"
port = 8000
transport = "otg"  # otg | wifi | manual

[[secuboxes.devices]]
id = "secubox-lab"
name = "SecuBox Lab"
host = "secubox-lab.local"
port = 8000
transport = "wifi"
```

---

## 8. Implementation Notes

### 8.1 Dependencies

**Python packages:**
- `fastapi` — Web framework
- `uvicorn` — ASGI server
- `pillow` — Framebuffer rendering (existing)
- `httpx` — Async HTTP client
- `websockets` — Real-time updates

**System tools:**
- `nmcli` — WiFi management (NetworkManager)
- `bluetoothctl` — Bluetooth management
- `systemctl` — Service control

### 8.2 Systemd Service

```ini
[Unit]
Description=SecuBox Eye Remote Agent
After=network.target pigpiod.service hyperpixel2r-init.service
Wants=pigpiod.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/secubox/eye-remote/agent/main.py
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### 8.3 Memory Constraints

Pi Zero W has 512MB RAM. Budget:
- Linux + services: ~150MB
- Python agent: ~50MB
- FastAPI server: ~30MB
- Framebuffer: ~1MB (480x480x2 bytes)
- **Total:** ~230MB, leaving ~280MB headroom

---

## 9. Testing Strategy

### 9.1 Unit Tests

- `test_mode_manager.py` — State machine transitions
- `test_failover.py` — Connection monitoring, timeout logic
- `test_wifi_manager.py` — nmcli wrapper
- `test_display_renderer.py` — Framebuffer output

### 9.2 Integration Tests

- Mode switching via Web Remote
- WiFi connect/disconnect cycles
- USB replug detection
- SecuBox API failover

### 9.3 Hardware Tests

- HyperPixel 2.1 Round display output
- USB OTG gadget enumeration
- WiFi + Bluetooth coexistence
- Long-running stability (24h+)

---

## 10. Rollout Plan

### Phase 1: Core Infrastructure
- Mode manager state machine
- Failover monitoring
- Refactor fb_dashboard.py into modular display/

### Phase 2: Display Modes
- Dashboard mode (existing, refactored)
- Local mode (new)
- Flash mode (new)
- Gateway mode (new)

### Phase 3: Web Remote
- FastAPI server integration
- Mode switching API
- Basic control.html UI

### Phase 4: System Controls
- WiFi manager (nmcli)
- Bluetooth manager (bluetoothctl)
- Display settings

### Phase 5: Advanced Features
- SecuBox device manager
- SecuBox remote control
- Gateway fleet aggregation

### Phase 6: Polish
- Service worker for offline
- WebSocket real-time updates
- Error handling and edge cases

---

## 11. Success Criteria

1. **Plug-and-play:** Insert SD, connect USB, display works immediately
2. **Auto-detection:** Dashboard mode when SecuBox present, Local when not
3. **Web control:** All features accessible via phone browser
4. **Failover:** Graceful degradation with clear visual feedback
5. **Stability:** 24h+ operation without crashes or memory leaks
6. **Resource usage:** <250MB RAM, <10% CPU idle

---

*CyberMind · SecuBox Eye Remote · Swiss Army Dashboard · 2026*
