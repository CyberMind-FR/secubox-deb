# secubox-eye-remote

Host-side integration for SecuBox Eye Remote (Pi Zero W + HyperPixel 2.1 Round).

## Features

- **Auto-detection**: udev rules detect Pi Zero USB gadget connection
- **Network**: Auto-configure 10.55.0.1/30 interface
- **API**: FastAPI endpoint for metrics relay and control
- **WebUI**: Control panel at /eye-remote/
- **Kernel 6.12**: Requires kernel with CONFIG_PHY_MVEBU_CP110_UTMI for MOCHAbin

## USB Gadget Modes

| Mode | Functions |
|------|-----------|
| normal | ECM Network + Serial |
| flash | Bootable USB + Serial |
| debug | Network + Storage + Serial |
| tty | HID Keyboard + Serial |
| auth | FIDO/U2F HID + QR display |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/eye-remote/status | Connection status |
| POST | /api/v1/eye-remote/connected | Notify connect (udev) |
| GET | /api/v1/eye-remote/metrics | Relay metrics from Eye |
| POST | /api/v1/eye-remote/mode | Change gadget mode |

## Requirements

- Kernel 6.12+ with CONFIG_PHY_MVEBU_CP110_UTMI=m (MOCHAbin)
- Tow-Boot 2022.07+ (for proper USB initialization)
- Pi Zero W with secubox-eye-gadget image

## Installation

```bash
apt install secubox-eye-remote
```

## Slipstream

Add to image build:
```bash
./image/build-image.sh --board mochabin --packages secubox-eye-remote
```
