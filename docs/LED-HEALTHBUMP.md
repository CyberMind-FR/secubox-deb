# SecuBox LED HealthBump System

**MOCHAbin 3-Tier Health Status Indicator**

The SecuBox HealthBump system uses the MOCHAbin's 3 RGB LEDs as a visual health status indicator, organized in a vertical "level meter" layout.

## LED Layout

```
┌─────────────────────────────────────────────────────────────┐
│                     MOCHAbin Front Panel                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────┐                                                   │
│   │ LED3│  TOP - Security Layer                             │
│   │ SEC │  Alerts, attacks, CrowdSec bans                   │
│   └─────┘                                                   │
│                                                              │
│   ┌─────┐                                                   │
│   │ LED2│  MIDDLE - Services Layer                          │
│   │ SVC │  VHosts, certificates, HAProxy                    │
│   └─────┘                                                   │
│                                                              │
│   ┌─────┐                                                   │
│   │ LED1│  BOTTOM - Hardware Layer                          │
│   │ HW  │  Network, CPU, memory                             │
│   └─────┘                                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Color Codes

| Color | Status | Meaning |
|-------|--------|---------|
| 🟢 Green | `ok` | All systems healthy |
| 🟡 Yellow | `warn` | Warning, attention needed |
| 🔴 Red | `error` | Critical, immediate action required |
| 🔵 Blue | `msg` | Information message, notification |

## LED Layers

### LED1 (Bottom) - Hardware Layer `hw`

Monitors base infrastructure health:

| Check | OK | Warning | Error |
|-------|----|---------| ------|
| WAN connectivity | Ping OK | - | No internet |
| CPU load | < 3.0 | > 3.0 | - |
| Memory | < 90% | > 90% | - |

### LED2 (Middle) - Services Layer `svc`

Monitors application services:

| Check | OK | Warning | Error |
|-------|----|---------| ------|
| HAProxy | Running | - | Stopped |
| Nginx | Running | - | Stopped |
| Certificates | Valid > 7d | Expiring < 7d | Expired |

### LED3 (Top) - Security Layer `sec`

Monitors security status:

| Check | OK | Warning | Error |
|-------|----|---------| ------|
| CrowdSec bans | 0 | 1-10 | > 10 |
| CrowdSec service | Running | - | Stopped |
| Active attacks | None | Low | High |

## Commands

### Manual LED Control

```bash
# Set individual layer status
secubox-led hw ok       # Hardware: green
secubox-led svc warn    # Services: yellow
secubox-led sec error   # Security: red
secubox-led hw msg      # Hardware: blue (info)

# Set all layers at once
secubox-led all ok      # All green
secubox-led all off     # All off

# Layer aliases
secubox-led 1 ok        # LED1 (hw)
secubox-led 2 warn      # LED2 (svc)
secubox-led 3 error     # LED3 (sec)

secubox-led bottom ok   # Same as hw
secubox-led middle warn # Same as svc
secubox-led top error   # Same as sec
```

### Automatic Health Check

```bash
# Run manual health check
secubox-healthbump

# Output example:
# LED1 (HW): ok
# LED2 (SVC): ok
# LED3 (SEC): warn
# 07:07:50 HW:ok SVC:ok SEC:warn
```

### Systemd Timer

The healthbump runs automatically every 30 seconds:

```bash
# Check timer status
systemctl status secubox-healthbump.timer

# View recent runs
journalctl -u secubox-healthbump.service --since "1 hour ago"

# Manually trigger
systemctl start secubox-healthbump.service
```

## Integration with Health Monitor

External systems can update LED status via the `secubox-led` command:

```bash
# From health monitor API callback
curl -X POST http://localhost:8080/health/callback \
  -d '{"layer": "sec", "status": "error", "reason": "Attack detected"}'

# The API internally calls:
secubox-led sec error
```

## Visual Status Examples

### All Healthy
```
LED3: 🟢 Security OK
LED2: 🟢 Services OK
LED1: 🟢 Hardware OK
```

### Security Alert
```
LED3: 🔴 ATTACK DETECTED
LED2: 🟢 Services OK
LED1: 🟢 Hardware OK
```

### Service Degraded
```
LED3: 🟢 Security OK
LED2: 🟡 Certificate expiring
LED1: 🟢 Hardware OK
```

### Network Down
```
LED3: 🟢 Security OK
LED2: 🟢 Services OK
LED1: 🔴 NO WAN CONNECTION
```

### Information Mode
```
LED3: 🔵 New update available
LED2: 🔵 Config pending
LED1: 🟢 Hardware OK
```

## Files

| File | Purpose |
|------|---------|
| `/usr/local/bin/secubox-led` | Manual LED control |
| `/usr/local/bin/secubox-healthbump` | Automatic health checker |
| `/etc/systemd/system/secubox-healthbump.service` | Oneshot service |
| `/etc/systemd/system/secubox-healthbump.timer` | 30s timer |

## Hardware

- **Controller**: ISSI IS31FL3199 (I2C address 0x64)
- **Bus**: I2C-1
- **Driver**: `leds-is31fl319x` (kernel built-in)
- **Sysfs**: `/sys/class/leds/{red,green,blue}:led{1,2,3}/`

## Related

- GitHub Issue #39: LED heartbeat port
- GitHub Issue #45: IS31FL3199 driver
- GitHub Issue #60: Kernel LED build
- `kernel-build/README.md`: Kernel build instructions

---

**CyberMind SecuBox** — https://secubox.in
