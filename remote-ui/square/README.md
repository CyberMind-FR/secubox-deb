# remote-ui/square — Eye Remote Square variant (Phase 3)

Phase 3: Pillow + framebuffer single-process kiosk. Targets Pi 4 Model B and
Pi 400 with the official Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480).

See [`docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md`](../../docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md)
for the full design.

## Hardware

| Board | Power | Display |
|---|---|---|
| Pi 4 Model B | GPIO 5V (USB-C reserved for peripheral OTG) | DSI 7" 800×480 V1.1 |
| Pi 400 | GPIO 5V | DSI or HDMI (same image works on both) |

## Process map

| systemd unit | Process |
|---|---|
| `secubox-firstboot.service` | one-shot: GPIO 5V check, hostname, SSH key, eye-square.toml bootstrap |
| `secubox-otg-gadget.service` | one-shot: configfs USB composite gadget (ECM + ACM + HID + mass-storage) |
| `secubox-eye-square-helper.service` | FastAPI on `/run/secubox/eye-square-helper.sock`, SO_PEERCRED auth |
| `secubox-square-kiosk.service` | the kiosk — Pillow renders 800×480 to /dev/fb0, evdev reads touch |

No X server, no Chromium, no Qt, no Openbox, no nginx.
