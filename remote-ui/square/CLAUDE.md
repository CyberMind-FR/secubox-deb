<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — remote-ui/square/

## Identity

Phase 3: Pillow+framebuffer single-process kiosk. Pi 4B / Pi 400 + 7" Touchscreen.

Phase 2 (Chromium+PySide6) was bench-tested then superseded — see PR #131
(closed). All Phase 2 right_panel / Chromium / Openbox / nginx code is gone.

## Stack

- Python 3.11 + Pillow 9.x + python-evdev 1.6 + httpx (sync UDS) + python-dateutil
- Helper FastAPI (carry-forward from Phase 2): FastAPI + uvicorn + websockets + SO_PEERCRED
- No X, no Qt, no Chromium, no Openbox, no nginx

## File map

```
packages/secubox-eye-square/
├── helper/                          carry-forward, 21 pytest cases green
├── debian/                          arm64 package — control updated for Phase 3 deps
└── kiosk/secubox_eye_square_kiosk/  the new Python kiosk
    ├── __main__.py                  event loop (30 FPS target)
    ├── framebuffer.py               /dev/fb0 mmap + BGRA blit
    ├── ring_dashboard.py            left 480x480 — 6 rings + pods + clock + transport badge + alert ribbon
    ├── right_panel.py               right 320x480 tab manager (tab bar + content routing)
    ├── tabs/
    │   ├── alerts.py                scrollable list
    │   ├── module_detail.py         gauge + sparkline
    │   ├── console.py               text scrollback + Freeze button
    │   └── mode_controls.py         USB mode + service + lockdown buttons (with confirm)
    ├── touch_input.py               python-evdev reader + classify (tap/long_tap/drag)
    ├── transport_manager.py         OTG/WiFi/SIM probe + JWT renewal + fetch_metrics
    ├── sim.py                       drift generator (port of round/fb_dashboard.py)
    ├── modules_table.py             6-entry MODULES dataclass list
    ├── helper_client.py             sync httpx UDS → helper FastAPI
    └── theme.py                     palette constants (matches round/'s literals)
```

## Run + debug

```bash
# Bench:
ssh secubox@<pi> 'systemctl status secubox-square-kiosk'
ssh secubox@<pi> 'journalctl -u secubox-square-kiosk -f'

# Local dev (without /dev/fb0):
EYE_SQUARE_FB=/tmp/fake-fb python3 -m secubox_eye_square_kiosk
# (truncate -s $((800*480*4)) /tmp/fake-fb first)
```

## Round/Pi Zero W is UNCHANGED

`remote-ui/round/fb_dashboard.py` is the canonical Pi Zero W deployment.
Phase 3 references it as inspiration but does NOT import from it. Touching
round/ in a Phase 3 commit is a bug.
