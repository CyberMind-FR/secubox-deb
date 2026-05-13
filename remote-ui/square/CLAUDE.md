# CLAUDE.md — remote-ui/square/

## Identity

Eye Remote Square variant. Pi 4B / Pi 400 + Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480).

## Stack

- Compositor: Openbox on X11
- Left pane (480×480): Chromium kiosk → `../round/index.html` (from `../common/`)
- Right pane (320×480): PySide6 (LGPL Qt) QMainWindow with 4 tabs
- IPC: ws://127.0.0.1:9090 (PySide6 hosts), Unix socket `/run/secubox/eye-square-helper.sock` (FastAPI helper hosts)

## Process map

| Unit | Process |
|---|---|
| `secubox-kiosk-x.service` | xinit on tty1 → Openbox + ~/.xinitrc |
| `secubox-otg-gadget.service` | configfs composite, VARIANT=square, GADGET_NAME=secubox-square |
| `secubox-eye-square-helper.service` | FastAPI on /run/secubox/eye-square-helper.sock |
| `secubox-square-chromium.service` | chromium --kiosk --app=file:///var/www/secubox-round/index.html --window-size=480,480 --window-position=0,0 |
| `secubox-square-right-panel.service` | python3 -m secubox_eye_square_right_panel |

## Key files

- `/var/www/common/` ← from remote-ui/common/
- `/var/www/secubox-round/index.html` ← from remote-ui/round/
- `/usr/lib/python3/dist-packages/eye_square_helper/` ← helper FastAPI
- `/usr/lib/python3/dist-packages/secubox_eye_square_right_panel/` ← right column
- `/etc/secubox/eye-square.toml` ← runtime config

## Power requirement

USB-C peripheral mode requires GPIO 5V power. Board powered via USB-C cannot enumerate as gadget. `firstboot.sh` enforces this at first boot via `/sys/class/power_supply/rpi-poe-power-supply/online` or `config.txt` `over_voltage` heuristic.

## Hardware variants

- Pi 4B → `/proc/device-tree/model` contains `Raspberry Pi 4 Model B`
- Pi 400 → contains `Raspberry Pi 400`. Same DTB family, same image, integrated keyboard handled automatically by libinput.
