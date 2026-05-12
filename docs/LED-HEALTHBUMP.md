<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox LED HealthBump System

**MOCHAbin 3-Tier Health Status Indicator** — v2.0

The SecuBox HealthBump system uses the MOCHAbin's 3 RGB LEDs as a visual health status indicator, organized in a vertical "level meter" layout.

> **v2.0 Changes**: Added 300ms I2C delays, timeout protection, and automatic I2C bus reset capability for reliable operation on Debian kernel 6.6.x LTS. Based on proven patterns from `secubox-led-safe`.

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
| 🟡 Yellow/Orange | `warn` | Warning, elevated activity |
| 🔴 Red | `error` | Critical, immediate action required |
| 🔵 Blue | `msg` | Active mitigation in progress |

## Brightness & I2C Timing

The IS31FL3199 LED controller uses brightness value **100** (active) or **20** (sleep) for optimal visibility with reliable I2C timing.

> **Important**: Uses same I2C timing values as `secubox-led-safe`:
> - `WRITE_DELAY=0.3` — 300ms between sysfs writes
> - `ERROR_BACKOFF=3` — 3 second wait after errors
> - `MAX_ERRORS=5` — Stop after 5 consecutive errors
> - `RESET_THRESHOLD=3` — Try I2C reset after 3 errors
> - `timeout 2` — 2 second max per write (prevents I2C lockup)

Higher values (e.g., 255) or faster timing cause I2C communication errors on Marvell Armada due to mv64xxx driver errata FE-8471889.

## Activity Detection

HealthBump monitors system changes and adjusts LED brightness:

| Mode | Brightness | Condition |
|------|------------|-----------|
| **ACTIVE** | 100 | Metrics changed (CPU, memory, bans, or colors) |
| **SLEEP** | 20 | System stable, no changes since last check |

This creates a visual "breathing" effect: brighter when activity occurs, dimmer when idle.

## K2000 Party Mode

For boot/success announcements and alerts:

```bash
# K2000 sweep effect
secubox-healthbump k2000 2 cyan    # 2 cycles, cyan color
secubox-healthbump party 1 green   # 1 cycle, green

# Success announcement (boot complete)
secubox-healthbump success "SecuBox ready"
secubox-healthbump boot            # Alias

# Alert (red K2000)
secubox-healthbump alert 2         # 2 cycles red

# Rainbow party (all colors)
secubox-healthbump rainbow
```

Colors: red, orange, yellow, green, cyan, blue, purple

## SPUNK ALERT

When critical services (HAProxy, CrowdSec) are down, all LEDs flash rapid red:

```
SPUNK ALERT: HAProxy down
```

The alert flashes 5 times then pauses 0.5s before rechecking. This overrides
normal health status until services recover.

## LED Layers

### LED1 (Bottom) - Hardware Layer `hw`

Monitors base infrastructure health with gradient colors:

| Resource Level | Color | Condition |
|----------------|-------|-----------|
| Normal | 🟢 Green | Load < 50%, Memory < 50% |
| Medium | 🟡 Yellow-Green | Load 50-70% |
| High | 🟠 Orange | Load 70-90% |
| Critical | 🔴 Red | Load > 90% OR No WAN |

### LED2 (Middle) - Services Layer `svc`

Monitors application services and certificates:

| Status | Color | Condition |
|--------|-------|-----------|
| OK | 🟢 Green | HAProxy + Nginx running, certs valid |
| Warning | 🟡 Yellow | Certificate expiring < 30 days |
| Error | 🔴 Red | Service stopped OR cert expired |

### LED3 (Top) - Security Layer `sec`

Monitors security with rate-based detection:

| Status | Color | Condition |
|--------|-------|-----------|
| Clear | 🟢 Green | 0 active bans |
| Mitigating | 🔵 Blue | Bans active, rate < 5/min |
| Elevated | 🟡 Yellow | Rate 5-20 bans/min |
| Attack | 🔴 Red | Rate > 20/min OR > 1000 bans |

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

# Output examples:
# 08:03:46 HW:[yellow:medium(50%cpu,53%mem)] SVC:[green:ok] SEC:[blue:mitigating(100 bans)]
# 08:15:22 HW:[green:ok(12%cpu,45%mem)] SVC:[green:ok] SEC:[green:clear]
# 08:30:01 HW:[red:no-wan] SVC:[green:ok] SEC:[yellow:elevated(50 bans,12/min)]
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
| `/usr/sbin/secubox-led-safe` | Safe LED control with I2C delays |
| `/usr/sbin/secubox-healthbump` | 3-tier health checker (v2.0) |
| `/etc/systemd/system/secubox-healthbump.service` | Oneshot health check unit |
| `/etc/systemd/system/secubox-healthbump.timer` | 30s health check timer |
| `/tmp/secubox/led-status` | Current LED status output |
| `/tmp/secubox-ban-rate` | CrowdSec ban rate tracking |

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
- `docs/reference/secubox-led-pulse-openwrt.sh`: Original OpenWrt LED script (single LED)

---

**CyberMind SecuBox** — https://secubox.in
