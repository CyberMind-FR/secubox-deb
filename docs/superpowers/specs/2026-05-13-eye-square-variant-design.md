<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Eye Remote — Square variant — Design

**Tracking issue:** [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
**Date:** 2026-05-13
**Author:** Gerald KERMA · CyberMind
**Status:** Draft, pending user review
**Predecessor:** [`remote-ui/round/`](../../../remote-ui/round/) v2.2.1
**Source concept:** SECUBOX·EYE·GADGET v0.1 (internal, CMSD-1.0)

---

## 1. Scope & non-goals

### Two-phase delivery

The work ships in two ordered PRs against two GitHub issues. Phase 1 must merge and pass round/ regression gates before Phase 2 starts.

### Phase 1 — extract `remote-ui/common/`, refactor round/ (no behavioral change)

Pull the parts of `remote-ui/round/` that are not Zero-W-specific into a new `remote-ui/common/` directory. Rewire round/'s `index.html`, `deploy.sh`, and `build-eye-remote-image.sh` to consume the extracted core. Round/'s end-state image must be a bit-for-bit equivalent to v2.2.1 modulo file timestamps, validated via `diffoscope`. Existing pytest suite and the v2.2.1 Zero W test bench both pass unchanged.

Items extracted to `common/`:
- `TransportManager` JS (OTG → WiFi → SIM probe)
- JWT helper, modules table (`AUTH`/`WALL`/`BOOT`/`MIND`/`ROOT`/`MESH` with colors and metric mapping), simulation drift generator
- Palette CSS (`--auth`, `--wall`, …) and base CSS (monospace, status row, pod base)
- 24 PNG icons (22/48/96/128 × six modules) and the `generate_icons.sh` cairosvg batch
- `secubox-otg-gadget.sh` and `secubox-otg-host-up.sh`, parameterised to accept a variant token

New optional hooks on `TransportManager` (default no-ops; round/ standalone unchanged):

```js
TransportManager.onModuleTap        = (module) => {};
TransportManager.onTransportChange  = (active) => {};
```

The host-side `RemoteUIManager` adds a `form_factor: "round" | "square"` field to `POST /api/v1/remote-ui/connected`, defaulting to `"round"` for backward compatibility.

### Phase 2 — add `remote-ui/square/` (purely additive)

New sibling targeting two boards that share the same BCM2711 SoC and image:

| | Pi 4 Model B (primary bench target) | Pi 400 (additional target) |
|---|---|---|
| SoC | BCM2711, arm64 | BCM2711, arm64 (identical silicon) |
| DTB | `bcm2711-rpi-4-b.dtb` | `bcm2711-rpi-400.dtb` |
| Display | Official Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480, 10-point capacitive) | DSI 7" panel via Pi 400's DSI connector, **or** micro-HDMI to external 800×480/1024×600 touchscreen (USB-touch device) |
| Keyboard | External USB | Integrated keyboard |
| Power | GPIO 5V (USB-C reserved for peripheral OTG) | GPIO 5V (USB-C reserved for peripheral OTG) |
| USB peripheral | dwc3 via `dwc2,dr_mode=peripheral` overlay | dwc3 via `dwc2,dr_mode=peripheral` overlay (identical) |

Shared across both:

| | Value |
|---|---|
| Compositor | Openbox on X11 (xinit-launched) |
| Renderer left | Chromium kiosk consuming `common/`+`round/index.html` at (0,0)+480×480 |
| Renderer right | PySide6 (LGPL Qt for Python) QMainWindow at (480,0)+320×480 |
| IPC | WebSocket on `ws://127.0.0.1:9090/eye-square` hosted by the PySide6 process |
| Privileged ops | `secubox-eye-square-helper` FastAPI on Unix socket `/run/secubox/eye-square-helper.sock` |
| Input | Touchscreen + USB touchpad + USB mouse + USB keyboard (Pi 400 adds integrated keyboard automatically via libinput) |

A single `secubox-eye-square_VERSION_arm64.img.xz` image boots on either board — the kernel's DTB selection at boot picks the right `bcm2711-rpi-*.dtb` based on the EEPROM model ID. `firstboot.sh` reads `/proc/device-tree/model` to record the board flavour and may set `hostname` accordingly (`secubox-eye-square-<6 hex>` on Pi 4B, `secubox-eye-square-400-<6 hex>` on Pi 400). All other configuration is identical.

### Out of scope (separate issues + specs)

- ZKP hardware tap-to-ACK (L1 twin per SECUBOX·EYE·GADGET concept v0.1)
- ALERTE·DÉPÔT signed deposit to MESH P2P (`did:plc` + WireGuard + Chain of Hamiltonians)
- Hamiltonian-path animated module visualisation
- Console tab write mode (touch on-screen keyboard for Pi 4B)
- Single hardware-agnostic image covering both Zero W (armhf) and Pi 4B (arm64) — Approach C was rejected as too invasive for v0.1

---

## 2. Repo layout

### Phase 1 — extraction into `remote-ui/common/`

```
remote-ui/
├── common/                              ← NEW (Phase 1)
│   ├── README.md
│   ├── js/
│   │   ├── transport-manager.js         ← extracted from round/index.html
│   │   ├── jwt-helper.js
│   │   ├── modules-table.js             ← AUTH/WALL/BOOT/MIND/ROOT/MESH defs
│   │   └── sim.js                       ← simulation drift generator
│   ├── css/
│   │   ├── palette.css                  ← :root vars (--auth, --wall, ...)
│   │   └── base.css                     ← monospace, status row, pod base
│   ├── assets/
│   │   ├── icons/                       ← 24 PNGs moved from round/assets/icons/
│   │   ├── svg/
│   │   └── generate_icons.sh
│   ├── shell/
│   │   ├── secubox-otg-gadget.sh        ← parametric (variant=round|square)
│   │   └── secubox-otg-host-up.sh
│   └── systemd/                         ← unit templates with @VARIANT@ tokens
│       ├── secubox-otg-gadget.service.in
│       └── secubox-serial-console.service.in
│
├── round/                               ← UNCHANGED file names, REWIRED contents
│   ├── index.html                       ← <link rel=stylesheet ../common/css/...>
│   │                                       <script src=../common/js/...>
│   ├── deploy.sh                        ← copies common/ + round/ to device
│   ├── build-eye-remote-image.sh        ← cps common/ into rootfs alongside round/
│   ├── fb_dashboard.py                  ← unchanged, ARMv6 fallback stays round-only
│   ├── install_zerow.sh                 ← unchanged
│   ├── README.md, CLAUDE.md             ← updated to reference common/
│   └── (everything else as-is)
│
└── README.md                            ← updated module table
```

### Phase 2 — add `remote-ui/square/`

```
remote-ui/square/                        ← NEW (Phase 2)
├── README.md
├── CLAUDE.md                            ← session-startup context modelled on round/CLAUDE.md
│
├── right_panel/                         ← native PySide6 right-column app
│   ├── __init__.py
│   ├── app.py                           ← QMainWindow, tab bar, geometry pin
│   ├── ipc_bridge.py                    ← qasync+websockets WS server on 127.0.0.1:9090
│   ├── helper_client.py                 ← async client for eye-square-helper Unix socket
│   ├── tabs/
│   │   ├── __init__.py
│   │   ├── alerts.py                    ← QListView, polls /api/v1/system/alerts
│   │   ├── module_detail.py             ← QGraphicsView sparkline + gauge
│   │   ├── console.py                   ← QTermWidget read-only tail of /dev/ttyACM0
│   │   └── mode_controls.py             ← QPushButton grid, USB gadget + service + lockdown
│   └── theme.py                         ← parses common/css/palette.css once at boot
│
├── helper/                              ← privileged FastAPI helper
│   ├── eye_square_helper/
│   │   ├── __init__.py
│   │   ├── app.py                       ← FastAPI factory, Unix socket bind
│   │   ├── routes/
│   │   │   ├── usb_gadget.py            ← POST /usb-gadget/mode
│   │   │   ├── console.py               ← GET /console/stream (WS bridge to /dev/ttyACM0)
│   │   │   ├── service.py               ← POST /service/restart
│   │   │   └── lockdown.py              ← POST /lockdown (nft ruleset swap)
│   │   └── auth.py                      ← peer cred check via SO_PEERCRED
│   └── tests/
│       ├── test_usb_gadget.py
│       ├── test_console.py
│       ├── test_service.py
│       └── test_lockdown.py
│
├── files/
│   ├── etc/secubox/eye-square.toml.example
│   ├── etc/openbox/autostart            ← geometry pins, xset s off -dpms, cursor visible
│   ├── etc/systemd/system/
│   │   ├── secubox-otg-gadget.service
│   │   ├── secubox-eye-square-helper.service
│   │   ├── secubox-square-chromium.service
│   │   ├── secubox-square-right-panel.service
│   │   └── secubox-kiosk-x.service
│   ├── etc/nginx/sites-available/secubox-square
│   ├── etc/udev/rules.d/90-secubox-otg-square.rules
│   └── usr/local/sbin/firstboot.sh
│
├── build-eye-square-image.sh            ← debootstrap Bookworm arm64 + kernel 6.x
├── install_pi4.sh                       ← flash + first-boot config (cousin of install_zerow.sh)
├── deploy.sh                            ← SSH-deploy hot updates
└── config.toml.example
```

### Phase 2 — Debian packaging

```
packages/secubox-eye-square/             ← NEW (Phase 2)
├── debian/
│   ├── control                          ← Architecture: arm64
│   ├── rules
│   ├── compat                           ← 13
│   ├── postinst                         ← systemctl enable --now the units
│   ├── prerm                            ← systemctl stop
│   └── changelog
├── etc/                                 ← shipped configs
└── usr/share/secubox-eye-square/        ← payload mounted from remote-ui/common/ + remote-ui/square/
```

Versioning: `1.0.0-1~bookworm1`. Standards-Version: 4.6.2.

The host-side `packages/secubox-eye-remote/` is **not** modified for v0.1. It already serves both Eye types; the only change is the new `form_factor` field added in Phase 1.

---

## 3. Dual-pane UI architecture

### Physical layout

Two OS-level windows side by side. No square-specific HTML page is created — Chromium consumes `round/index.html` directly.

```
┌──────────────────────────────────────────────────────────────┐
│  Compositor: Openbox on X11                                  │
│                                                              │
│  ┌─────────────────────┬──────────────────────────────┐      │
│  │                     │  ┌─ Qt tab bar ────────────┐ │      │
│  │  Chromium kiosk     │  │ ALERTS  DETAIL  CON  M  │ │      │
│  │  --app=file://...   │  └─────────────────────────┘ │      │
│  │  /usr/share/        │  ┌─────────────────────────┐ │      │
│  │  secubox-eye-       │  │                         │ │      │
│  │  square/round/      │  │   Active tab QWidget    │ │      │
│  │  index.html         │  │                         │ │      │
│  │  --window-size=     │  │                         │ │      │
│  │  480,480            │  │   PySide6 QMainWindow   │ │      │
│  │  --window-position= │  │   geometry 320x480      │ │      │
│  │  0,0                │  │   +480+0                │ │      │
│  │                     │  │                         │ │      │
│  │   480 × 480         │  │   320 × 480             │ │      │
│  └─────────────────────┴──────────────────────────────┘      │
│                                                              │
│  Touch / mouse / touchpad / keyboard events routed by libinput│
│  and X to whichever window contains the pointer.             │
└──────────────────────────────────────────────────────────────┘
```

### Process map

| Process | Unit | Role |
|---|---|---|
| `Xorg` | `secubox-kiosk-x.service` | Single X server on `:0` started via `xinit` |
| `openbox` | started by `~secubox/.xinitrc` | WM, places windows from `autostart` |
| `chromium --app=file:///.../round/index.html --kiosk --window-size=480,480 --window-position=0,0` | `secubox-square-chromium.service` | Renders round UI from `common/`+`round/` |
| `python3 -m eye_square.right_panel` | `secubox-square-right-panel.service` | PySide6 right column + WS bridge server |
| `uvicorn eye_square_helper.app:app --uds /run/secubox/eye-square-helper.sock` | `secubox-eye-square-helper.service` | Privileged ops, runs as `secubox-eye-square` system user |

### IPC matrix

```
                    ┌─────────────────────────────────┐
                    │  Chromium (round/index.html)    │
                    │  TransportManager from common/  │
                    └─────────────┬───────────────────┘
                                  │
                  (1) HTTPS/JSON ─┤                    (3) WS over loopback only
                                  ├──────────────► ws://127.0.0.1:9090/eye-square
                  to SecuBox      │              "module:tap", "transport:status"
                  host API on     ▼
                  OTG or WiFi   ┌──────────────────────────────┐
                                │  PySide6 right_panel         │
                                │  qasync + websockets server  │
                                │  bound 127.0.0.1:9090        │
                                │  4 tab QWidgets              │
                                └──────────┬───────────────────┘
                                           │
                              (2) HTTP+WS via Unix socket
                                           ▼
                                ┌─────────────────────────────┐
                                │  eye-square-helper FastAPI  │
                                │  - POST /usb-gadget/mode    │
                                │  - GET  /console/stream WS  │
                                │  - POST /service/restart    │
                                │  - POST /lockdown           │
                                │ AmbientCapabilities=        │
                                │  CAP_NET_ADMIN CAP_SYS_ADMIN│
                                │ User=secubox-eye-square     │
                                └─────────────────────────────┘
```

### How round/'s standalone behaviour is preserved

`common/js/transport-manager.js` exposes `onModuleTap` and `onTransportChange` as default no-op hooks. In round/'s standalone deployment they stay no-ops. In square/'s deployment, the Chromium command line adds an extra `<script>` tag (served by nginx from `/usr/share/secubox-eye-square/square-bridge.js`) that overrides the hooks to forward events over the loopback WebSocket. Round/'s `index.html` and round/'s image are unaffected.

### Toolkit choice

**PySide6** (LGPL Qt for Python). PyQt6 (GPL) conflicts with CMSD-1.0 proprietary licensing; GTK4 is viable but PySide6 has stronger touch ergonomics and a mature embedded-terminal widget (`QTermWidget`) for the Console tab. Debian packages: `python3-pyside6.qtwidgets`, `python3-pyside6.qtwebsockets`. If `python3-qtermwidget` does not link cleanly against PySide6 on Bookworm arm64, fallback is a custom `QPlainTextEdit` + asyncio PTY reader — same UX, ~150 lines.

---

## 4. Right column tab design

320×480 portrait. 56 px tab bar across the top, 424 px content area below. Tab bar uses `var(--cosmos-black)`; the currently selected tab is bordered in `var(--gold-hermetic)` and tinted the active module's colour when a `module:tap` from the round UI just routed here.

### Tab 1 — Alerts (`tabs/alerts.py`)

`QListView` backed by a `QAbstractListModel`. Polls `/api/v1/system/alerts` every 2 s **directly** against the SecuBox host API — the helper FastAPI is reserved for local privileged operations only. The right panel learns the current base URL (OTG `10.55.0.1` vs WiFi `secubox.local` vs SIM) from the `transport:status` event emitted by Chromium's TransportManager over the loopback WebSocket. Row format: `[severity dot] HH:MM:SS  module  message`. Dot colour from `common/css/palette.css`. Tapping a row opens the alert's module in Tab 2.

Empty state: centred `● NOMINAL` in matrix-green.

### Tab 2 — Module detail (`tabs/module_detail.py`)

Default content when round UI fires `module:tap`.

```
┌──────────────────────────────────┐
│  [icon-96] AUTH                  │  module title row, colour-coded
│            cpu_percent           │  metric this module surveils
├──────────────────────────────────┤
│  ███████████████████████░░░░░░░  │  gauge (gradient on threshold)
│  47.2%                           │
├──────────────────────────────────┤
│  60s sparkline (QGraphicsScene   │  rolling 60-sample line chart
│   polyline)                      │
│                                  │
├──────────────────────────────────┤
│  Service: secubox-auth   ● active│
│  PID 1234 · up 3h17              │
│  Last alert: 2026-05-12 14:22    │
└──────────────────────────────────┘
```

Data sources (all existing endpoints):
- Gauge + sparkline: `GET /api/v1/system/metrics`
- Service status: `GET /api/v1/system/modules`
- Last alert: filtered from the alerts feed

Tap the module title bar to cycle through the six modules. Long-press the title to toggle "follow the round UI's tapped module" auto-follow.

### Tab 3 — Console (`tabs/console.py`)

`QTermWidget` if available, otherwise `QPlainTextEdit` + asyncio PTY reader. **v0.1 is read-only** — no on-screen keyboard. Subscribes to `ws://localhost/local/console/stream` (nginx proxy to the helper FastAPI), which does `tail -f` on `/dev/ttyACM0` in satellite mode or `journalctl -u 'secubox-*' -f` in kiosk mode (selection driven by current TransportManager state).

Auto-scroll on, with a "freeze" button bottom-right to halt scrolling for inspection.

### Tab 4 — Mode controls (`tabs/mode_controls.py`)

Grid of 80×80 `QPushButton`s:

```
┌──────────────────────────────────┐
│  USB GADGET MODE                 │
│  [NORMAL ✓]  [FLASH]   [DEBUG]   │
│  [TTY    ]   [AUTH ]   [STOP ]   │
├──────────────────────────────────┤
│  SECUBOX SERVICE                 │
│  [RESTART HUB]   [RESTART AUTH]  │
│  [RESTART ALL]   [LOCKDOWN  !]   │
├──────────────────────────────────┤
│  TRANSPORT                       │
│  [● OTG] [● WiFi] [○ SIM]        │  current TM state; tap = force re-probe
└──────────────────────────────────┘
```

Every button POSTs to the helper FastAPI. Modal `QDialog` confirms irreversible actions (FLASH, STOP, LOCKDOWN, RESTART ALL); confirmation requires a 2-second hold of the dialog's confirm button to defeat accidental taps.

USB gadget mode buttons reuse the same configfs sequences as `common/shell/secubox-otg-gadget.sh`. Mode switch is atomic: `stop → reconfigure → start`. Current mode is read from `/sys/kernel/config/usb_gadget/secubox/UDC` plus a sidecar state file.

### Auto-tab-switch behaviour

| Event source | Triggers | Behaviour |
|---|---|---|
| Round UI module:tap | `podTap()` in round/index.html | Right panel switches to Tab 2, loads tapped module. Round UI's existing pod opacity flash stays. |
| New alert ≥ warn | helper pushes `alerts:new` over WS | **No auto-switch by default** (`auto_switch_on_alert = false` in `eye-square.toml`). Operator can enable. |
| Transport state change | TM broadcasts `transport:status` over WS | Tab 4 Transport indicator updates; no tab switch. |
| Idle 5 min on Tab 2/3/4 | Qt `QTimer` | Auto-return to Tab 1 (alerts). Configurable. |

### Input

Touchscreen + USB touchpad + USB mouse + USB keyboard are all first-class. Qt and Chromium unify pointer events via libinput; no per-device branching in the application code. Cursor is **always visible** (no auto-hide). All UI affordances reachable by single click — no swipe-required navigation. USB keyboard is enabled passively; Ctrl+Alt+F2 remains available for admin escape to a getty.

---

## 5. USB gadget & dual-mode on Pi 4B

This section only documents what changes from round/ because Pi 4B is not Zero W. The TransportManager logic itself (OTG → WiFi → SIM) is preserved verbatim in `common/`.

### Controller difference

|  | Pi Zero W (round/) | Pi 4 Model B (square/) |
|---|---|---|
| USB controller | dwc2 (BCM2835) | dwc3 (BCM2711, USB-C port only) |
| Kernel module | `dwc2` | `dwc3` (mainline Bookworm arm64) |
| Mode select | `dtoverlay=dwc2` + `options dwc2 dr_mode=peripheral` | `dtoverlay=dwc2,dr_mode=peripheral` (the same overlay name gates dwc3 dual-role on Pi 4B) |
| OTG cable | micro-USB DATA port | USB-C port, board powered separately via GPIO |

### Power requirement (critical)

Pi 4B's USB-C is power+data on the same physical port. To use it as a USB peripheral, the board **must be powered through GPIO header 5V**, not through USB-C. The first-boot script enforces this:

```bash
# files/usr/local/sbin/firstboot.sh
if [ "$(cat /sys/class/power_supply/rpi-poe-power-supply/online 2>/dev/null)" != "1" ] && \
   ! grep -q '^over_voltage' /boot/firmware/config.txt; then
    cat <<EOF >&2
SECUBOX-EYE-SQUARE: USB-C peripheral mode requires GPIO 5V power.
Power the Pi 4B through GPIO pins 2 (5V) and 6 (GND), or through PoE HAT.
If powered via USB-C, USB gadget cannot enumerate as peripheral.
EOF
    systemctl mask secubox-otg-gadget.service
    exit 1
fi
```

Power-source requirement is documented in `remote-ui/square/README.md` as a deployment prerequisite.

### `/boot/firmware/config.txt` deltas

```ini
# Display: official Raspberry Pi 7" Touchscreen V1.1 (DSI)
dtoverlay=vc4-kms-v3d
display_auto_detect=1

# USB gadget on USB-C port
dtoverlay=dwc2,dr_mode=peripheral

# Disable serial getty on UART (host-side console is via USB ACM)
enable_uart=0
```

### `/etc/modules`

```
dwc2
libcomposite
configfs
```

### Composite gadget functions

`common/shell/secubox-otg-gadget.sh` instantiates the same five modes round/ supports (Normal / Flash / Debug / TTY / Auth). Function-to-mode mapping unchanged.

Square-specific tweak: MAC address derivation reads `/sys/firmware/devicetree/base/serial-number` on arm64 (Pi 4B), falling back to the existing `/proc/cpuinfo` Serial path used by round/. `common/` handles both via a try-list.

### Host-side detection

When square/ plugs into a SecuBox host:

1. The host's existing `/etc/udev/rules.d/90-secubox-otg.rules` matches by USB VID:PID of the SecuBox composite gadget. Square/ uses the same VID:PID as round/, so no host-side rule changes.
2. Phase 1 generalises the udev-driven interface rename (today: `secubox-round`) to a configurable name so square's interface can be `secubox-square` or a generic `secubox-eye-<serial>`.
3. The `POST /api/v1/remote-ui/connected` payload from Phase 1 includes the new `form_factor: "round" | "square"` field. Defaults to `"round"` for back-compat.

### Dual-mode resolution

No square-specific branching. "Kiosk mode" and "satellite mode" are emergent from which probe succeeds:

```
1. http://10.55.0.1:8000/api/v1/health   (OTG path) ──► active="OTG"
                                                       USB gadget is the data path
2. http://secubox.local:8000/api/v1/health (WiFi)   ──► active="WiFi"
                                                       USB gadget runs but unused
3. neither responds                                 ──► active="SIM" drift mode
```

Tab 4's TRANSPORT row in the right panel can force a re-probe but cannot manually pin a mode (matches round/'s "automatic, observable" philosophy).

---

## 6. Build pipeline & deployment

### Image build — `remote-ui/square/build-eye-square-image.sh`

Modelled on `remote-ui/round/build-eye-remote-image.sh`, retargeted:

1. Download Raspberry Pi OS Lite Bookworm arm64 (.img.xz)
2. `xzcat` → mount loopback (boot + root partitions)
3. `qemu-aarch64-static` + `chroot` mount-bind
4. `apt-get install` (inside chroot):
   - `chromium`, `openbox`, `xserver-xorg`, `xinit`
   - `python3-pyside6.qtwidgets`, `python3-pyside6.qtwebsockets`
   - `python3-qtermwidget` (with custom fallback if linker fails)
   - `python3-fastapi`, `python3-uvicorn`, `python3-websockets`, `qasync`
   - `nginx-light`
   - `secubox-eye-square` (from local `.deb` or `apt.secubox.in`)
5. Patch `/boot/firmware/config.txt` with Section 5 deltas
6. Write `/etc/modules`
7. Install systemd units from `files/etc/systemd/system/`, enable them
8. Install `firstboot.sh`, mark for one-shot
9. Unmount, compress → `secubox-eye-square_VERSION_arm64.img.xz`

Output ~600-800 MB compressed.

### First-boot — `remote-ui/square/files/usr/local/sbin/firstboot.sh`

Runs once on the device:

1. Power-source validation (Section 5)
2. Resize root partition to fill SD
3. Generate machine-id, set hostname `secubox-eye-square-<6 hex from serial>`
4. Import SSH `authorized_keys` from `/boot/firmware/secubox-key.pub` if present, then delete the file
5. Bootstrap JWT credential by reading `/boot/firmware/secubox-eye-square.toml` (operator-supplied), copy to `/etc/secubox/eye-square.toml`, `chmod 600`, `chown root:secubox-eye-square`
6. `systemctl enable --now` the four square services
7. Disable itself for subsequent boots

### SD card flashing — `remote-ui/square/install_pi4.sh`

Cousin of `install_zerow.sh` with the same option grammar (`-d -i -s -p -k -h -u`), but:

- Validates device is NOT `/dev/sda`, `/dev/nvme0n1`, `/dev/mmcblk0`
- Confirmation prompt before erasing
- Drops a `secubox-eye-square.toml` template on the boot partition
- Optional `-w` flag pre-writes WiFi credentials to `wpa_supplicant.conf` for kiosk-mode operators
- No `-r` (USB OTG) flag — gadget mode is always configured, gated by Section 5's power check at runtime

### Hot-update deployment — `remote-ui/square/deploy.sh`

For incremental updates without reflashing. SSH-based, mirrors round/'s `deploy.sh`:

- Copies `remote-ui/common/` + `remote-ui/square/` to `/usr/share/secubox-eye-square/` on the device
- Patches `eye-square.toml` from CLI overrides (`--api-url`, `--api-pass`, `--sim`, `--no-sim`)
- `systemctl restart secubox-eye-square-helper secubox-square-chromium secubox-square-right-panel` — gadget and X server stay running across the update
- `curl -k https://localhost:8080/` smoke test

### Debian packaging — `packages/secubox-eye-square/`

```
debian/control:
    Source: secubox-eye-square
    Section: admin
    Priority: optional
    Maintainer: Gerald KERMA <devel@cybermind.fr>
    Standards-Version: 4.6.2

    Package: secubox-eye-square
    Architecture: arm64
    Depends:
        secubox-core,
        secubox-eye-remote,
        chromium, openbox, xserver-xorg, xinit,
        python3-pyside6.qtwidgets, python3-pyside6.qtwebsockets,
        python3-fastapi, python3-uvicorn, python3-websockets,
        nginx-light
    Description: SecuBox Eye Remote — Square variant (Pi 4B + 7" 800x480)
```

Versioning: `1.0.0-1~bookworm1` per project rule. Built on the same CI workflow that produces other arm64 packages (`.github/workflows/build-packages.yml`).

---

## 7. Services & systemd ordering

```
                        ┌──────────────────────────────┐
                        │ multi-user.target            │
                        └──────────────┬───────────────┘
                                       │
        ┌──────────────────────────────┼────────────────────────────┐
        ▼                              ▼                             ▼
┌────────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│ secubox-otg-gadget     │  │ secubox-eye-square-  │  │ nginx                │
│ .service               │  │ helper.service       │  │                      │
│ (configfs composite,   │  │ (FastAPI on Unix     │  │ proxy /local/* →     │
│ from common/shell/)    │  │  socket; runs as     │  │ helper.sock,         │
│ After: sys-kernel-     │  │  secubox-eye-square  │  │ serves static round/ │
│  config.mount          │  │  user)               │  │ index.html           │
└────────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
             │                         │                         │
             └─────────────────────────┴─────────────────────────┘
                                       │
                                       ▼
                        ┌─────────────────────────────────┐
                        │ secubox-kiosk-x.service         │
                        │ (xinit on tty1, brings up X     │
                        │  and Openbox via ~/.xinitrc)    │
                        └──────────────┬──────────────────┘
                                       │
                                       ▼
                        ┌─────────────────────────────────┐
                        │ graphical.target                │
                        └──────────────┬──────────────────┘
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
        ┌──────────────────────────┐  ┌──────────────────────────┐
        │ secubox-square-chromium  │  │ secubox-square-right-    │
        │ .service                 │  │ panel.service             │
        │ Type=simple              │  │ Type=simple              │
        │ User=secubox             │  │ User=secubox             │
        │ Environment=DISPLAY=:0   │  │ Environment=DISPLAY=:0   │
        │ ExecStart=chromium       │  │ ExecStart=python3 -m     │
        │  --kiosk                 │  │  eye_square.right_panel  │
        │  --app=file:///...       │  │ Restart=always           │
        │  --window-size=480,480   │  │ MemoryMax=384M           │
        │  --window-position=0,0   │  │                          │
        │ Restart=always           │  │ (hosts WS server on      │
        │ MemoryMax=512M           │  │  127.0.0.1:9090)         │
        └──────────────────────────┘  └──────────────────────────┘
```

Notes:

- Openbox `autostart` sets cursor visibility, disables screen blanking (`xset s off -dpms`), and pins window geometries via matching rules so Chromium lands at (0,0)+480×480 and PySide6 at (480,0)+320×480.
- Helper service runs as `secubox-eye-square` system user with `AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN` — not root. `CAP_NET_ADMIN` for `nft` lockdown ruleset swap; `CAP_SYS_ADMIN` for configfs writes during USB gadget mode switching.
- AppArmor profile shipped in `debian/` and activated in `postinst` per CSPN rule.

---

## 8. Testing

### Phase 1 regression gates (must pass before Phase 2 starts)

1. `bash scripts/build-packages.sh` produces an identical-named round/ deb (version unchanged).
2. `bash remote-ui/round/build-eye-remote-image.sh` produces an image whose `diffoscope` diff against v2.2.1 shows only file-timestamp deltas.
3. Manual: flash the new image onto the Zero W test bench (board accessible at `ssh root@192.168.1.200`), boot, verify dashboard renders identically.
4. `pytest secubox/tests/test_remote_ui.py -v` — existing tests stay green.

### Phase 2 acceptance gates

1. `bash remote-ui/square/build-eye-square-image.sh` produces a flashable image.
2. Flash onto the Pi 4B + 7" panel test bench:
   - Boot < 30 s to dashboard visible.
   - Round UI renders at (0,0) — 480×480.
   - Right panel renders at (480,0) — 320×480, defaults to Alerts tab.
   - Touch a pod in the round UI → right panel switches to Module Detail with that module loaded.
   - Touch Console tab → output visible (`/dev/ttyACM0` tail in satellite mode, or `journalctl` tail in kiosk mode).
   - Touch Mode controls → buttons render; pressing FLASH shows confirmation dialog; releasing before 2 s does not commit.
3. Plug into a SecuBox MOCHAbin host:
   - Host sees the gadget, udev renames interface to `secubox-eye-<id>`.
   - Host's `/api/v1/remote-ui/connected` receives `form_factor=square`.
   - Round UI badge shows `● OTG`.
4. Unplug USB → wait 30 s → square re-probes and either (a) badge changes to `● WiFi` if WiFi configured, or (b) drops to `○ SIM`.
5. USB touchpad and USB mouse both move the cursor and click. USB keyboard types into focused widget.
6. `pytest packages/secubox-eye-square/helper/tests/ -v` — mode switch, console stream, service restart, lockdown.
7. `shellcheck` clean on all square/ shell scripts.

### CI

- `.github/workflows/build-packages.yml` gains a job for `secubox-eye-square` arm64 build.
- `.github/workflows/build-image.yml` gains an optional job (manual dispatch only — image build is heavy) for `build-eye-square-image.sh`.

---

## 9. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| `python3-qtermwidget` does not link cleanly against PySide6 on Bookworm arm64 | Medium | Fallback path is a custom `QPlainTextEdit` + asyncio PTY reader (~150 LOC). Decided at Phase 2 start during dependency probe. |
| Phase 1 refactor accidentally changes round/'s wire behaviour | Low (gated) | Regression gates 1-4 catch this before Phase 2 begins. `diffoscope` SHA equivalence is hard evidence. |
| Pi 4B USB-C peripheral mode + GPIO power combo is fragile in the field | Medium | First-boot script bails loudly. README documents prerequisite. Future hardware revision could add a level shifter on a dedicated micro-USB. |
| Two windows pinned by Openbox drift / get covered by stray dialogs | Low | Both Chromium and PySide6 run with `--no-window-decoration` / `setWindowFlag(Qt.FramelessWindowHint)`; Openbox matching rules force `<above>` and `<decor>no</decor>`. No other GUI apps run on the device. |
| Helper FastAPI capabilities (`CAP_SYS_ADMIN` for configfs) widen attack surface | Medium | Helper authenticates clients via `SO_PEERCRED` (only `secubox-eye-square` UID accepted); AppArmor profile confines syscalls; lockdown action audit-logged to `/var/log/secubox/audit.log` per CSPN rule. |
| Image size growth from Chromium + Qt pushes past 1 GB compressed | Low | Trim apt cache, strip debug symbols, drop unused Qt modules at build time. If still over budget, Buildroot path (issue #79) becomes the long-term answer. |

---

## 10. References

- [`remote-ui/round/README.md`](../../../remote-ui/round/README.md) — predecessor module documentation
- [`remote-ui/round/CLAUDE.md`](../../../remote-ui/round/CLAUDE.md) — round/ session-startup context
- Tracking issue: [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
- Related issue: [#79](https://github.com/CyberMind-FR/secubox-deb/issues/79) — Buildroot minimal image
- Project rules: [`CLAUDE.md`](../../../CLAUDE.md), [`.claude/CLAUDE.md`](../../../.claude/CLAUDE.md)
- Source concept: SECUBOX·EYE·GADGET v0.1 (internal)
- Hardware: Raspberry Pi 4 Model B (BCM2711, arm64), Raspberry Pi Display V1.1 (DSI, 800×480)
- Toolkit: [PySide6](https://doc.qt.io/qtforpython-6/) (LGPL Qt for Python)
- Compositor: [Openbox](http://openbox.org/) on X11
