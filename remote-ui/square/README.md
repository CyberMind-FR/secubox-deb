# remote-ui/square — Eye Remote Square variant

Hardware:
- Raspberry Pi 4 Model B (BCM2711, arm64) — primary bench target
- Raspberry Pi 400 (same SoC) — also supported, integrated keyboard

Display: Official Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480, 10-point capacitive).

Layout:
- Chromium kiosk at (0, 0, 480, 480) consuming `../common/` + `../round/index.html` verbatim
- PySide6 right column at (480, 0, 320, 480) with four tabs: Alerts, Module Detail, Console, Mode Controls
- IPC: Chromium → PySide6 over `ws://127.0.0.1:9090/eye-square` (Chromium uses the bridge override in `square-bridge.js`)
- Privileged operations: `secubox-eye-square-helper` FastAPI on Unix socket `/run/secubox/eye-square-helper.sock`

**Critical power requirement:** USB-C peripheral mode requires GPIO 5V power input. Powering via USB-C disables the USB gadget path. `firstboot.sh` enforces this at first boot.

See [docs/superpowers/specs/2026-05-13-eye-square-variant-design.md](../../docs/superpowers/specs/2026-05-13-eye-square-variant-design.md) for the full design.
