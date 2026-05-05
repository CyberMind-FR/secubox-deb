# SecuBox Modem

LTE/5G modem management module for SecuBox-DEB.

## Overview

`secubox-modem` provides full-featured management for Quectel LTE/5G modems connected via mPCIe or USB. It uses a hybrid approach combining ModemManager for connection lifecycle and qmicli for detailed signal/info queries.

## Features

- **Auto-Detection**: Automatically detects any plugged Quectel modem (EC25, RM500Q, EM12, etc.)
- **Connection Management**: Connect/disconnect with APN configuration
- **SMS**: Send and receive SMS messages via WebUI
- **AT Terminal**: Interactive WebSocket-based AT command console
- **Signal Monitoring**: Real-time signal strength with historical graphs
- **Device Info**: IMEI, IMSI, firmware version, SIM info

## Supported Modems

| Model | Type | Interface |
|-------|------|-----------|
| EC25 | LTE Cat 4 | mPCIe/USB |
| EC21 | LTE Cat 1 | mPCIe/USB |
| EP06 | LTE Cat 6 | M.2/USB |
| EM12 | LTE Cat 12 | M.2 |
| RM500Q | 5G Sub-6 | M.2 |
| RM520N | 5G Sub-6 + mmWave | M.2 |
| RG500Q | 5G | M.2 |

## API Endpoints

### Status & Info

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/modem/status` | Connection state, operator, signal |
| GET | `/api/v1/modem/info` | IMEI, IMSI, firmware, model |
| GET | `/api/v1/modem/signal` | Current signal metrics (RSSI, RSRP, SINR) |
| GET | `/api/v1/modem/signal/history` | Signal history for graphing |
| GET | `/api/v1/modem/detection` | Modem detection summary |
| GET | `/api/v1/modem/sim` | SIM card information |
| GET | `/api/v1/modem/network` | Network/cell info |
| GET | `/health` | Health check |

### Connection Management

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/modem/connect` | Connect with APN config |
| POST | `/api/v1/modem/disconnect` | Disconnect cellular |
| GET | `/api/v1/modem/config` | Current connection config |
| POST | `/api/v1/modem/config` | Update APN/PIN config |
| POST | `/api/v1/modem/power/on` | Power on modem |
| POST | `/api/v1/modem/power/off` | Power off modem |
| POST | `/api/v1/modem/reset` | Reset modem |
| GET | `/api/v1/modem/apn/database` | Known APN configurations |

### SMS

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/modem/sms` | List all SMS messages |
| POST | `/api/v1/modem/sms/send` | Send SMS |
| GET | `/api/v1/modem/sms/{id}` | Get specific SMS |
| DELETE | `/api/v1/modem/sms/{id}` | Delete SMS |
| POST | `/api/v1/modem/sms/delete-all` | Delete all SMS |
| GET | `/api/v1/modem/sms/stats` | SMS statistics |

### AT Terminal

| Method | Path | Description |
|--------|------|-------------|
| WebSocket | `/api/v1/modem/at/console` | Interactive AT console |
| POST | `/api/v1/modem/at/command` | Single AT command (REST) |
| GET | `/api/v1/modem/at/test` | Quick AT test |
| GET | `/api/v1/modem/at/info` | Get info via AT |
| GET | `/api/v1/modem/at/signal` | Get signal via AT+CSQ |
| GET | `/api/v1/modem/at/port` | Detected AT port |

## WebUI

Access the dashboard at `https://<host>/modem/`

### Tabs

1. **Status** - Connection state, operator, network type, modem info, signal bars
2. **Signal** - Real-time signal chart (RSRP/RSSI/SINR), history, statistics
3. **SMS** - Message inbox, compose, delete
4. **Terminal** - Interactive AT command console via WebSocket
5. **Settings** - APN configuration, known APNs database, modem control

## Configuration

### `/etc/secubox/modem.toml`

```toml
[modem]
enabled = true
refresh_interval = 30
signal_history_hours = 1

[connection]
auto_connect = false
apn = "orange.m2m.spec"
ip_type = "ipv4"
auth = "none"
user = ""

[sms]
enabled = true
max_stored = 100

[terminal]
enabled = true
baudrate = 115200
```

### Secrets

SIM PIN and password are stored separately for security:

- `/etc/secubox/secrets/modem-pin` - SIM PIN (chmod 600)
- `/etc/secubox/secrets/modem-password` - APN password (chmod 600)

## Dependencies

### Debian Packages

```
secubox-core
modemmanager
libqmi-utils
libmbim-utils
picocom
python3-serial
```

### Python Packages

```
fastapi
uvicorn
pydantic
websockets
pyserial-asyncio (optional)
```

## Installation

```bash
apt install secubox-modem
```

Or build from source:

```bash
cd packages/secubox-modem
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../secubox-modem_*.deb
```

## Service Management

```bash
# Status
systemctl status secubox-modem

# Logs
journalctl -u secubox-modem -f

# Restart
systemctl restart secubox-modem
```

## Testing

### Check Modem Detection

```bash
curl -s https://localhost/api/v1/modem/detection | jq
```

### Check Signal

```bash
curl -s https://localhost/api/v1/modem/signal | jq
```

### Connect

```bash
curl -X POST https://localhost/api/v1/modem/connect \
  -H "Content-Type: application/json" \
  -d '{"apn": "internet"}'
```

### Send SMS

```bash
curl -X POST https://localhost/api/v1/modem/sms/send \
  -H "Content-Type: application/json" \
  -d '{"number": "+33612345678", "text": "Test from SecuBox"}'
```

### AT Command

```bash
curl -X POST https://localhost/api/v1/modem/at/command \
  -H "Content-Type: application/json" \
  -d '{"command": "AT+CSQ"}'
```

## Troubleshooting

### Modem Not Detected

1. Check USB connection: `lsusb | grep -i quectel`
2. Check ModemManager: `mmcli -L`
3. Check kernel modules: `lsmod | grep -E 'qmi|cdc'`
4. Install usb-modeswitch if needed: `apt install usb-modeswitch`

### Connection Fails

1. Verify APN is correct for your carrier
2. Check SIM card: `mmcli -m 0 --sim`
3. Check registration: `mmcli -m 0 | grep -i state`
4. Try AT command: `AT+CREG?`

### Serial Port Access Denied

Ensure secubox user is in dialout group:

```bash
usermod -a -G dialout secubox
systemctl restart secubox-modem
```

## Architecture

```
┌──────────────┐     ┌──────────────┐
│   WebUI      │────>│  FastAPI     │
│  (Browser)   │     │    API       │
└──────────────┘     └──────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        v                   v                   v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ ModemManager │   │   qmicli     │   │  AT Serial   │
│   (mmcli)    │   │  (detailed   │   │  (direct     │
│              │   │   queries)   │   │   access)    │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                   │
       └──────────────────┴───────────────────┘
                          │
                          v
                  ┌──────────────┐
                  │   Quectel    │
                  │    Modem     │
                  └──────────────┘
```

## License

Proprietary - CyberMind / ANSSI CSPN candidate

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
