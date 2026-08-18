<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# remote-ui/square — Eye Remote Square variant (Phase 3)

Phase 3: Pillow + framebuffer single-process kiosk targeting Raspberry Pi
4 Model B and Raspberry Pi 400 with the official Raspberry Pi 7" Touchscreen
V1.1 (DSI, 800×480, 10-point capacitive).

Companion to the [`round/`](../round/) Pi Zero W variant (also Pillow+fb).

See [`docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md`](../../docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md)
for the full design.

## Hardware

| Board | Power | Display |
|---|---|---|
| Pi 4 Model B | GPIO 5V (USB-C reserved for peripheral OTG) | DSI 7" 800×480 V1.1 |
| Pi 400 | GPIO 5V | DSI or HDMI (same image works on both) |

## Process map

| systemd unit | Purpose |
|---|---|
| `secubox-firstboot.service` | one-shot: GPIO 5V check, hostname, SSH key, eye-square.toml |
| `secubox-otg-gadget.service` | configfs USB composite gadget (ECM+ACM+HID+mass-storage) |
| `secubox-eye-square-helper.service` | FastAPI on /run/secubox/eye-square-helper.sock, SO_PEERCRED |
| `secubox-square-kiosk.service` | the kiosk — Pillow renders 800×480 to /dev/fb0, evdev reads touch |

No X server, no Chromium, no Qt, no Openbox, no nginx.

## Boot sequence

1. Pi OS first-boot (regenerates SSH host keys, removes init= from cmdline, reboot)
2. Pi OS normal boot + multi-user.target activates:
   - `secubox-firstboot.service` runs once (sets hostname, imports SSH key)
   - `secubox-otg-gadget.service` configures USB peripheral mode
   - `secubox-eye-square-helper.service` starts FastAPI on Unix socket
   - `secubox-square-kiosk.service` opens /dev/fb0 + /dev/input/event*, renders dashboard

## Build

```bash
sudo bash remote-ui/square/build-eye-square-image.sh -o /tmp
```

Produces `/tmp/secubox-eye-square_VERSION_arm64.img.xz` (~400 MB compressed).

## Deploy

```bash
sudo bash remote-ui/square/install_pi4.sh \
    -d /dev/sdX \
    -i /tmp/secubox-eye-square_*.img.xz \
    -s "<WiFi-SSID>" -p "<WiFi-PSK>" \
    -k ~/.ssh/id_ed25519.pub
```

For hot updates on a running Pi:

```bash
bash remote-ui/square/deploy.sh -h <pi-ip>
```
