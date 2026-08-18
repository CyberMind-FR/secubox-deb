<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Eye Remote — Phase 3 (Python+framebuffer kiosk for Pi 4B/400)

**Tracking issue:** [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
**Supersedes:** Phase 2 PR [#131](https://github.com/CyberMind-FR/secubox-deb/pull/131) (Chromium + PySide6 dual-window approach — closed in favour of this design after bench-test feedback)
**Date:** 2026-05-13
**Author:** Gerald KERMA · CyberMind
**Status:** Draft, pending user review
**Predecessor reference:** `remote-ui/round/fb_dashboard.py` (Pi Zero W Pillow+fb dashboard, **unchanged**)

---

## 1. Scope & non-goals

### Why Phase 3 supersedes Phase 2

Phase 2 shipped a dual-window kiosk: Chromium rendering `round/index.html` at (0,0)+480×480 and a PySide6 `QTabWidget` at (480,0)+320×480, with WebSocket IPC between them. Bench-test on Pi 4B + 7" Touchscreen V1.1 succeeded after debugging:

- 5 plan-vs-reality fix commits (PySide6 via pip, OTG script symlinks, Pi OS userconfig masking, libxcb-* deps, Chromium `--kiosk` drop)
- Operator-confirmed dual-screen render
- Helper FastAPI + OTG link end-to-end working

But the resulting architecture is fragile (window-stacking races, Chromium focus-grab covering the right panel) and heavy (~400 MB RAM idle, ~1.5 GB compressed image). The operator requested an all-Python single-process kiosk aligned with `remote-ui/round/fb_dashboard.py`'s approach for the Pi Zero W variant. Phase 3 delivers that.

### Hardware

| | Pi 4 Model B (primary bench target) | Pi 400 |
|---|---|---|
| SoC | BCM2711, arm64 | BCM2711, arm64 (identical silicon) |
| DTB | `bcm2711-rpi-4-b.dtb` | `bcm2711-rpi-400.dtb` |
| Display | Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480, 10-point capacitive) | DSI 7" panel **or** HDMI external |
| Keyboard | External USB | Integrated |
| Power | GPIO 5V (USB-C reserved for peripheral OTG) | GPIO 5V |
| USB peripheral | dwc3 via `dwc2,dr_mode=peripheral` | dwc3 via `dwc2,dr_mode=peripheral` |

A single `secubox-eye-square_VERSION_arm64.img.xz` boots on either board. The kernel picks the right `bcm2711-rpi-*.dtb` at boot. `firstboot.sh` differentiates hostname by `/proc/device-tree/model`.

### In scope

- New `remote-ui/square/kiosk/` directory: single Python process that uses **Pillow** to draw the full 800×480 frame and `mmap` `/dev/fb0` to push the bytes.
- Left half (480×480): "Round dashboard" — 6 concentric rings, 6 pods, central clock, transport badge, status row, temperature bar. Pixel-faithful intent vs Phase 1's round/ but **independently authored** (does not import from `round/`).
- Right half (320×480): "Right panel" — 4 tabs (Alerts / Module Detail / Console / Mode Controls) drawn manually with Pillow.
- Touch input via `python3-evdev` reading `/dev/input/event*` for the DSI touchscreen and any plugged-in mouse/keyboard.
- TransportManager + simulation drift + modules table, ported from `remote-ui/common/js/` to `remote-ui/square/kiosk/`.
- Helper FastAPI on Unix socket — **reused verbatim** from Phase 2 (USB gadget mode switch, service restart, lockdown, console stream).
- Debian packaging `packages/secubox-eye-square/` — same shell as Phase 2, dependency list trimmed massively (no Qt, no X, no Chromium, no nginx, no libxcb-*).
- Build script `remote-ui/square/build-eye-square-image.sh` — same flow as Phase 2, smaller package set.
- Phase 2's helper FastAPI tests, debian packaging, firstboot.sh — **carried forward unchanged**.

### Modernisation deltas vs Phase 1's round/ (intentional differences)

- Smooth ring fill animations: ease-in-out over 250 ms via Pillow tweening between metric readings.
- Modules loaded from `modules_table.py` as a dataclass list (typed, easier to iterate).
- Alerts ribbon overlay at the bottom 24 px of the round canvas when severity ≥ warn (auto-fade 5 s).
- Helper-driven service/mode controls in the right panel (round/ has no equivalent).

### Out of scope

- `remote-ui/round/fb_dashboard.py` — untouched. Pi Zero W deployment stays exactly as v2.2.1.
- `remote-ui/common/` JS/CSS — also untouched. Common/ exists for the HTML-Chromium path (round/index.html for Phase 1's nginx-served deployment) and `square/` Phase 3 doesn't consume it.
- PySide6, Qt, Chromium, X server, Openbox, nginx — all removed from the Phase 3 image.
- Wayland — deferred to a future migration when Pi OS Trixie lands.
- Multi-arch single image — Phase 3 ships arm64 only (Pi 4B/400). Pi Zero W keeps its armhf image from Phase 1.
- ZKP hardware tap-to-ACK, ALERTE·DÉPÔT signed deposit, hamiltonian-path animation — separate specs.

---

## 2. Repo layout

### Carries forward from Phase 2 (unchanged)

```
packages/secubox-eye-square/
├── helper/                            ← FastAPI on /run/secubox/eye-square-helper.sock
│   ├── eye_square_helper/
│   │   ├── app.py                     SO_PEERCRED auth + router includes
│   │   ├── auth.py                    ALLOWED_UIDS resolver
│   │   ├── __main__.py                uvicorn UDS bind
│   │   └── routes/
│   │       ├── usb_gadget.py          POST /usb-gadget/mode + GET /usb-gadget/state
│   │       ├── service.py             POST /service/restart (allow-list)
│   │       ├── lockdown.py            POST /lockdown (nft swap)
│   │       └── console.py             WS /console/stream (tail tty or journalctl)
│   └── tests/                         24 pytest cases (auth + 4 routes + e2e)
└── debian/                            arm64 package shell, postinst, prerm
```

### New in `remote-ui/square/kiosk/`

```
remote-ui/square/
├── README.md                          ← updated for Phase 3
├── CLAUDE.md                          ← updated for Phase 3
├── kiosk/                             ← NEW Phase 3 root
│   ├── __init__.py
│   ├── __main__.py                    event loop driver
│   ├── framebuffer.py                 /dev/fb0 mmap helper, RGB565/BGRA blit
│   ├── ring_dashboard.py              left 480×480 Pillow renderer
│   ├── right_panel.py                 right 320×480 tab manager
│   ├── tabs/
│   │   ├── __init__.py
│   │   ├── alerts.py                  scrollable alerts list
│   │   ├── module_detail.py           gauge + sparkline
│   │   ├── console.py                 text scrollback
│   │   └── mode_controls.py           touch-button grid
│   ├── touch_input.py                 python-evdev reader, coord mapping
│   ├── transport_manager.py           Python port of common/js/transport-manager.js
│   ├── sim.py                         drift generator
│   ├── modules_table.py               RINGS dataclass list
│   ├── helper_client.py               sync httpx UDS to helper FastAPI
│   ├── theme.py                       palette (no parser needed — hardcoded for Phase 3)
│   └── tests/                         pytest cases (no Qt, no offscreen needed)
└── files/
    └── etc/
        ├── systemd/system/
        │   ├── secubox-eye-square-helper.service   ← unchanged from Phase 2
        │   ├── secubox-otg-gadget.service          ← unchanged from Phase 2
        │   ├── secubox-firstboot.service           ← unchanged from Phase 2
        │   └── secubox-square-kiosk.service        ← NEW (replaces 3 Phase 2 units)
        ├── apparmor.d/secubox-eye-square-helper    ← unchanged
        ├── udev/rules.d/90-secubox-otg-square.rules ← unchanged
        └── secubox/eye-square.toml.example         ← unchanged
        — etc/openbox/                              ← DROPPED
        — etc/nginx/                                ← DROPPED (helper UDS called directly)
        — home/secubox/.xinitrc                     ← DROPPED
```

### Removed from Phase 2

- `packages/secubox-eye-square/right_panel/` (entire PySide6 widget tree + tests)
- `remote-ui/square/square-bridge.js`
- `remote-ui/square/files/etc/openbox/{autostart,rc.xml}`
- `remote-ui/square/files/etc/nginx/sites-available/secubox-square`
- `remote-ui/square/files/home/secubox/.xinitrc`
- systemd units: `secubox-kiosk-x.service`, `secubox-square-chromium.service`, `secubox-square-right-panel.service`

---

## 3. Rendering architecture

### Frame buffer

Pi 4B's DSI panel exposes `/dev/fb0` at 800×480, 32-bit BGRA (the `vc4-kms-v3d` overlay's framebuffer layout). `framebuffer.py`:

```python
import mmap
class FrameBuffer:
    def __init__(self, path="/dev/fb0", width=800, height=480, bpp=4):
        self.fd = os.open(path, os.O_RDWR)
        self.size = width * height * bpp
        self.fb = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_WRITE)
        self.width, self.height, self.bpp = width, height, bpp

    def blit(self, pil_image: Image.Image):
        """Push a Pillow image to /dev/fb0. PIL Image must be in BGRA mode at exact resolution."""
        assert pil_image.size == (self.width, self.height)
        # PIL → BGRA bytes (vc4-kms uses little-endian BGRA32)
        self.fb.seek(0)
        self.fb.write(pil_image.tobytes("raw", "BGRA"))
```

`vcgencmd get_lcd_info` confirms 32-bit BGRA on the official 7" panel. RGB565 fallback path exists in `round/fb_dashboard.py` if needed for other panels.

### Event loop

30 FPS target. Each tick:

1. Read pending touch events (non-blocking, with poll/select)
2. Update transport manager + simulation state (every 2 s, not every frame)
3. Update right panel based on touch / module:tap events
4. Re-render left half (ring_dashboard.draw → PIL `Image`)
5. Re-render right half (right_panel.draw → PIL `Image`)
6. Composite into one 800×480 PIL frame
7. Push to framebuffer

Skip-rendering optimisation: if no state changed, don't redraw; sleep until either a touch event or the next 2 s metric tick.

### Ring dashboard (left 480×480)

`ring_dashboard.py` draws:

| Element | Geometry | Source |
|---|---|---|
| 6 concentric arcs | Radii 214, 201, 188, 175, 162, 149 px (centred at 240,240) | `modules_table.py` RINGS list |
| 6 module pods | Around the ring | Same |
| Central clock | 240,240 ± ~40 px | local time, 1 Hz updates |
| Hostname + uptime | Under clock | `/proc/uptime` + `socket.gethostname()` |
| Transport badge | Top-right | `transport_manager.active` |
| Status row | Bottom area | "● NOMINAL" / "▲ MODULE val" depending on alerts |
| Temperature bar | Bottom | ROOT module value (`cpu_temp`) |

Animations: when a metric changes between ticks, `QPropertyAnimation`-equivalent in pure Python — store `current` and `target` per ring, ease over 8 frames (~250 ms at 30 FPS).

### Right panel (right 320×480)

`right_panel.py` owns:
- Tab bar at top 56 px (4 buttons, each 80×56, gold-bordered when active)
- Content area 320×424

Tab dispatch: the currently-active tab's `draw(image, region)` is called each frame. The `module:tap` callback (fired by `ring_dashboard` on a pod tap) switches the active tab to Module Detail and passes the tapped module.

Tab implementations (all in `tabs/`):
- **alerts.py**: 16-row scrollable list. Each row: severity dot (8 px) + time + module name + truncated message. Scroll via touch drag. 
- **module_detail.py**: title bar (gold) + 60 px gauge (rounded bar with fill) + 80 px sparkline (line graph, 60 samples) + 60 px service-status text.
- **console.py**: text scrollback (12 visible lines × 12 px). Auto-scroll on append. "FREEZE" toggle button bottom-right.
- **mode_controls.py**: 6 USB-mode buttons (2 rows × 3) + 4 service buttons (2 rows × 2) + transport indicator. Destructive actions (flash, stop, restart-all, lockdown) trigger a confirm overlay.

### Touch input

`touch_input.py` uses python-evdev:

```python
from evdev import InputDevice, ecodes

def open_devices():
    devices = []
    for path in glob.glob("/dev/input/event*"):
        dev = InputDevice(path)
        if "touchscreen" in dev.name.lower() or ecodes.EV_ABS in dev.capabilities():
            devices.append(dev)
    return devices

def read_events(devices):
    # non-blocking via select.select(devices, [], [], 0)
    for dev in select.select(...):
        for event in dev.read():
            if event.type == ecodes.EV_ABS and event.code == ecodes.ABS_X:
                ...
```

Tap = `BTN_TOUCH` press → release within 250 ms at same coord ± 10 px. Drag = release > 10 px from press → scroll a list.

Coord mapping: touch (0..32767, 0..32767) → screen (0..800, 0..480). May need calibration — easier than X11's xinput-cal. For the Pi 4B 7" V1.1 the mapping is linear and 1:1 to screen pixels.

### Transport manager + simulation

`transport_manager.py` ports `common/js/transport-manager.js` to Python:
- `probe()`: try HTTP HEAD on http://10.55.0.1:8000/api/v1/health → OTG. Else http://secubox.local:8000/api/v1/health → WiFi. Else SIM.
- `login()`, `ensure_jwt()`, `fetch_metrics()` — same logic as JS.
- Hooks `on_module_tap`, `on_transport_change` are Python callbacks (no WebSocket needed — same process).

`sim.py` ports `common/js/sim.js`. Drift generator.

### Helper client (in-process)

`helper_client.py` uses `httpx.Client(transport=httpx.HTTPTransport(uds="/run/secubox/eye-square-helper.sock"))` — sync HTTP over Unix socket. The 4 methods (`set_usb_mode`, `restart_service`, `lockdown`, `tail_console`) wrap the helper FastAPI routes from Phase 2.

For the console tab, instead of WS, use a generator that tails a subprocess:
```python
def tail_console():
    proc = subprocess.Popen(["journalctl", "-f", "-u", "secubox-*"], stdout=PIPE)
    for line in iter(proc.stdout.readline, b""):
        yield line.decode().rstrip()
```

(If we want the helper-mediated console for proper PI-side `/dev/ttyACM0` access, helper still exposes `/console/stream` and we use httpx streaming.)

---

## 4. systemd

One service replaces three:

```ini
# /etc/systemd/system/secubox-square-kiosk.service
[Unit]
Description=SecuBox Eye Square — Pillow+framebuffer kiosk
After=multi-user.target secubox-eye-square-helper.service
Wants=multi-user.target secubox-eye-square-helper.service
ConditionPathExists=/dev/fb0

[Service]
Type=simple
User=secubox
Group=secubox
SupplementaryGroups=video input
ExecStart=/usr/bin/python3 -m secubox_eye_square_kiosk
Restart=always
RestartSec=3
MemoryMax=128M
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1

[Install]
WantedBy=multi-user.target
```

- `User=secubox` (read fb0 needs video group + write needs root-ish — Pillow direct fb writes work for secubox in video group with `/dev/fb0` chmod 660 root:video on Pi OS Lite)
- `SupplementaryGroups=video input` — for `/dev/fb0` write + `/dev/input/event*` read
- `MemoryMax=128M` — ~30-50M typical, 128 is generous
- `WantedBy=multi-user.target` — no graphical.target dependency anymore

### Boot-time service list

Phase 3's image enables only these:
- `ssh.service`
- `secubox-firstboot.service` (oneshot, completes on first boot)
- `secubox-otg-gadget.service`
- `secubox-eye-square-helper.service`
- `secubox-square-kiosk.service`

Drop: `secubox-kiosk-x`, `secubox-square-chromium`, `secubox-square-right-panel`, `nginx`, getty@tty1 (masked).

---

## 5. Debian packaging

`packages/secubox-eye-square/debian/control` shrinks to:

```
Source: secubox-eye-square
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2

Package: secubox-eye-square
Architecture: arm64
Depends:
 ${misc:Depends},
 ${python3:Depends},
 secubox-core,
 secubox-eye-remote,
 python3-pil,
 python3-evdev,
 python3-fastapi,
 python3-uvicorn,
 python3-websockets,
 python3-httpx,
 apparmor-utils
Description: SecuBox Eye Remote — Square variant (Pi 4B / Pi 400 + 7" 800x480)
 Pillow-on-framebuffer single-process kiosk. Renders the SecuBox dashboard
 directly to /dev/fb0 — no X server, no Qt, no Chromium. Companion to the
 round/ Pi Zero W variant (also Pillow+fb).
 .
 Includes a privileged Helper FastAPI on a Unix socket for USB gadget mode
 switching, service restart, lockdown (nftables atomic swap), and console
 streaming.
```

Compare to Phase 2's: drops `chromium`, `openbox`, `xserver-xorg`, `xinit`, `unclutter`, `python3-pyside6.qtwidgets`, `python3-pyside6.qtwebsockets`, `python3-qasync`, `nginx-light`. Adds `python3-pil`, `python3-evdev`.

---

## 6. Build pipeline

`remote-ui/square/build-eye-square-image.sh` shrinks substantially:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3-pil python3-evdev \
    python3-fastapi python3-uvicorn python3-websockets \
    python3-httpx \
    apparmor-utils
# No more libxcb-*, no pip install pyside6, no openbox, no chromium, no nginx
```

Image size estimate: **~400 MB compressed** (vs Phase 2's 1.5 GB).

`config.txt` gets the same overlays as Phase 2:
```
dtoverlay=vc4-kms-v3d
display_auto_detect=1
dtoverlay=dwc2,dr_mode=peripheral
enable_uart=0
```

`firstboot.sh` is unchanged.

---

## 7. Testing

### Unit tests (no display needed)

- `framebuffer.py`: mock `/dev/fb0` via `tmpfs` file, verify blit byte counts + offsets
- `ring_dashboard.py`: render a known input → snapshot PIL image, compare against golden
- `right_panel.py` + each `tab`: same snapshot-based approach
- `touch_input.py`: feed synthetic evdev events, verify dispatch
- `transport_manager.py`: mock HTTP, verify OTG/WiFi/SIM transitions + JWT renewal
- `helper_client.py`: existing Phase 2 tests carry forward (httpx mocking)
- `sim.py`: deterministic seed, verify drift bounds

Estimated ~30 new pytest cases. Helper tests (24) stay green.

### Bench test (Pi 4B + 7" V1.1)

- Boot < 20 s to kiosk visible (Phase 2 was ~60 s)
- 30 FPS render confirmed (`vmstat` showing low CPU between ticks)
- Touch a pod → right panel switches to Module Detail
- Plug into MOCHAbin → OTG link comes up, transport badge changes to "● OTG"
- USB touchpad + mouse + keyboard all work (libinput → evdev)

### Pi 400 sanity

Same image flashed to Pi 400 → hostname `secubox-eye-square-400-XXXXXX` → kiosk renders identically (DSI or HDMI). Integrated keyboard accepted via evdev.

---

## 8. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| 30 FPS in pure Python with Pillow may strain Pi 4B CPU | Medium | Profile early. Pillow is C-implemented; ring drawing per frame is <50 ms on Pi 4B benchmark. Skip-rendering when state unchanged. |
| Touch coord mapping wrong on 7" V1.1 (calibration) | Medium | Phase 1's fb_dashboard.py establishes precedent; we copy its coord mapping. If wrong, log raw events and tune offsets. |
| /dev/fb0 access requires root on some Pi OS configs | Low | Add `udev` rule shipping `chmod 660 /dev/fb0` + `chown root:video` on boot. secubox user is in video group. |
| Anti-aliasing on rings looks worse than Canvas's smooth arcs | Medium | Pillow `ImageDraw.arc()` is good enough; supplement with `aggdraw` if needed. |
| Helper FastAPI's WebSocket /console/stream won't work without nginx | Low | Use httpx streaming (`client.stream("GET", "/console/stream")`) directly to the helper UDS. No nginx needed. |
| Estimating 25-30 hours; could blow up if Pillow performance is worse than expected on Pi 4B | Medium | Prototype the ring rendering in week 1 of execution. Measure FPS. Pivot to PySide6+eglfs if Pillow is unworkable. |
| Plan-vs-reality bugs (same kind as Phase 2's PySide6/xcb saga) | High | Two-stage review per task. Be willing to dispatch fix loops. |

---

## 9. References

- [`remote-ui/round/fb_dashboard.py`](../../../remote-ui/round/fb_dashboard.py) — Pi Zero W Pillow+fb reference (1,367 lines, **untouched**)
- [`remote-ui/round/index.html`](../../../remote-ui/round/index.html) — Phase 1 Chromium-rendered round UI (visual design reference)
- Phase 2 PR [#131](https://github.com/CyberMind-FR/secubox-deb/pull/131) — superseded by this design
- Tracking issue: [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
- Pillow docs: https://pillow.readthedocs.io
- python-evdev: https://python-evdev.readthedocs.io
- Linux framebuffer interface: https://www.kernel.org/doc/Documentation/fb/framebuffer.txt
