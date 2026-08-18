<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote Multigadget System

**SecuBox Eye Remote** — Multi-mode USB gadget for remote monitoring, recovery, and authentication.

**Hardware:** Raspberry Pi Zero W + HyperPixel 2.1 Round (480×480)
**Connection:** USB OTG composite gadget (ECM + ACM + optional Mass Storage/HID)

---

## Table of Contents

- [Autorun System](#autorun-system)
- [Guest/Host Storage Rebound](#guesthost-storage-rebound)
- [Round UI Dashboard](#round-ui-dashboard)
- [CyberMind Tooling](#cybermind-tooling)
- [Quick Reference](#quick-reference)

---

## Autorun System

The Eye Remote boots as a USB composite gadget with configurable modes.

### USB Gadget Modes

| Mode | Functions | Network | Serial | Storage | HID | Use Case |
|------|-----------|---------|--------|---------|-----|----------|
| **Normal** | ECM + ACM | 10.55.0.2 | ttyGS0 | - | - | Dashboard monitoring |
| **Flash** | Mass Storage | - | - | Boot ISO | - | Recovery boot |
| **Debug** | ECM + ACM + Mass | 10.55.0.2 | ttyGS0 | Logs | - | Export diagnostics |
| **TTY** | ACM + HID | - | ttyGS0 | - | Keyboard | U-Boot automation |
| **Auth** | FIDO2 HID | - | - | - | Security Key | Hardware 2FA |

### Boot Sequence

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Power on Pi Zero W                                       │
│    └─► dwc2 kernel module loads (dr_mode=peripheral)        │
│                                                             │
│ 2. Systemd reaches multi-user.target                        │
│    └─► secubox-otg-gadget.service starts                    │
│                                                             │
│ 3. configfs gadget created                                  │
│    └─► /sys/kernel/config/usb_gadget/secubox/               │
│        ├── functions/ecm.usb0     (network)                 │
│        ├── functions/acm.usb0     (serial)                  │
│        └── UDC = fe980000.usb                               │
│                                                             │
│ 4. Network interface usb0 comes up                          │
│    └─► IP: 10.55.0.2/30, Gateway: 10.55.0.1                 │
│                                                             │
│ 5. Dashboard connects to SecuBox API                        │
│    └─► http://10.55.0.1:8000/api/v1/system/metrics          │
└─────────────────────────────────────────────────────────────┘
```

### Mode Switching

```bash
# SSH to Eye Remote
ssh pi@10.55.0.2

# Switch to TTY mode (for U-Boot access)
sudo secubox-otg-gadget.sh tty

# Switch to Flash mode (presents boot ISO)
sudo secubox-otg-gadget.sh flash

# Return to Normal mode
sudo secubox-otg-gadget.sh start

# Check current status
sudo secubox-otg-gadget.sh status
```

### Key Files

| File | Purpose |
|------|---------|
| `/usr/local/sbin/secubox-otg-gadget.sh` | Gadget mode manager |
| `/etc/systemd/system/secubox-otg-gadget.service` | Autostart service |
| `/etc/modprobe.d/secubox-otg.conf` | dwc2 peripheral mode |
| `/etc/network/interfaces.d/usb0` | Static IP config |

---

## Guest/Host Storage Rebound

Boot media management with double-buffer architecture and 4R rollback.

### Architecture

```
/var/cache/secubox/boot-media/
│
├── active/                    ← Live boot media
│   ├── KERNEL                   vmlinuz
│   ├── INITRD                   initrd.img
│   ├── DTB                      device tree blob
│   ├── metadata.json            version, hash, timestamp
│   └── integrity.sha256         checksums
│
├── shadow/                    ← Staging area
│   ├── (same structure)
│   └── pending_swap.flag        set during upload
│
└── rollback/                  ← 4 generations
    ├── R1/                      most recent rollback
    ├── R2/
    ├── R3/
    └── R4/                      oldest rollback
```

### Swap Protocol (Atomic)

```
┌──────────────────────────────────────────────────────────────┐
│ 1. VALIDATE                                                  │
│    └─► SHA256(shadow/KERNEL) == expected_hash?               │
│                                                              │
│ 2. SYNC                                                      │
│    └─► fsync() all files in shadow/                          │
│                                                              │
│ 3. ARCHIVE                                                   │
│    └─► mv active/ → R1/, shift R1→R2→R3→R4                   │
│                                                              │
│ 4. SWAP (atomic)                                             │
│    └─► mv -T shadow/ active/                                 │
│                                                              │
│ 5. CLEANUP                                                   │
│    └─► rm pending_swap.flag, mkdir shadow/                   │
└──────────────────────────────────────────────────────────────┘
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | Current active/shadow state |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload file to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Atomic swap active↔shadow |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Restore from R1-R4 |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | TFTP server status |

### Example: Upload and Swap

```bash
# Get current state
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state

# Upload new kernel to shadow
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "file=@vmlinuz-6.1.0" \
  -F "target=KERNEL" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload

# Swap with validation
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"validate_hash": "abc123..."}' \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap

# Rollback to R2
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"rollback_target": 2}' \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback
```

---

## Round UI Dashboard

Circular 480×480 display with real-time SecuBox metrics.

### 6-Ring Status Display

```
        ┌────────────────────────────────────────┐
        │              AUTH (CPU)                │  ← Outer ring
        │         ┌──────────────────┐           │
        │         │    WALL (MEM)    │           │
        │         │  ┌────────────┐  │           │
        │         │  │ BOOT(DISK)│  │           │
        │         │  │ ┌────────┐ │  │           │
        │         │  │ │  MIND  │ │  │           │
        │         │  │ │ (LOAD) │ │  │           │
        │         │  │ │┌──────┐│ │  │           │
        │         │  │ ││ ROOT ││ │  │           │
        │         │  │ ││(TEMP)││ │  │           │
        │         │  │ │└──────┘│ │  │           │
        │         │  │ │  MESH  │ │  │           │
        │         │  │ │ (WiFi) │ │  │           │
        │         │  │ └────────┘ │  │           │
        │         │  └────────────┘  │           │
        │         └──────────────────┘           │
        └────────────────────────────────────────┘
```

| Ring | Module | Metric | Color | Threshold |
|------|--------|--------|-------|-----------|
| 1 (outer) | AUTH | CPU % | #C04E24 | 70% warn, 85% crit |
| 2 | WALL | MEM % | #9A6010 | 75% warn, 90% crit |
| 3 | BOOT | DISK % | #803018 | 80% warn, 95% crit |
| 4 | MIND | Load avg | #3D35A0 | 2.0 warn, 4.0 crit |
| 5 | ROOT | Temp °C | #0A5840 | 65° warn, 75° crit |
| 6 (inner) | MESH | WiFi dBm | #104A88 | -70 warn, -80 crit |

### Center Display

```
┌─────────────────────┐
│      14:32:07       │  ← Time (1Hz update)
│    mer 15 avril     │  ← Date (localized)
│    secubox-zero     │  ← Hostname
│      up 24h00       │  ← Uptime
└─────────────────────┘
```

### Radial Menu (Long-press Center)

```
           DEVICES
              │
    EXIT ─────┼───── SECUBOX
              │
   SECURITY ──┼── LOCAL
              │
          NETWORK
```

| Menu | Submenus |
|------|----------|
| **DEVICES** | Scan, Pair, Forget |
| **SECUBOX** | Status, Modules, Logs, Restart |
| **LOCAL** | Display, Network, System, About |
| **NETWORK** | Interfaces, Routes, DNS, Firewall |
| **SECURITY** | Alerts, Bans, Rules, Audit, Lockdown |
| **EXIT** | Dashboard, Sleep, Reboot, Shutdown |

### Transport Manager

Priority: OTG → WiFi → Simulation

```
┌─────────────────────────────────────────────┐
│ TM.probe()                                  │
│                                             │
│ 1. Try OTG: http://10.55.0.1:8000/health    │
│    ├─► OK  → active = "OTG" (green badge)   │
│    └─► FAIL 3× → try WiFi                   │
│                                             │
│ 2. Try WiFi: http://secubox.local:8000/     │
│    ├─► OK  → active = "WiFi" (blue badge)   │
│    └─► FAIL → active = "SIM" (gray badge)   │
│                                             │
│ Re-probe every 30 seconds                   │
└─────────────────────────────────────────────┘
```

---

## CyberMind Tooling

Scripts for building, deploying, and managing Eye Remote devices.

### Install Scripts

| Script | Purpose | Example |
|--------|---------|---------|
| `install_zerow.sh` | Flash SD card for Pi Zero W | `sudo ./install_zerow.sh -d /dev/sdX -i raspios.img.xz -s WiFiSSID -p WiFiPass` |
| `prep_zerow_hyperpixel.sh` | Configure HyperPixel display | `./prep_zerow_hyperpixel.sh` |
| `deploy.sh` | Deploy dashboard via SSH | `./deploy.sh -h 10.55.0.2 --api-url http://10.55.0.1:8000` |

### HID Keyboard Automation

```bash
# Send single command to U-Boot
./secubox-hid-keyboard.sh cmd 'printenv'

# Send boot command
./secubox-hid-keyboard.sh cmd 'boot'

# Queue multiple commands
./secubox-hid-keyboard.sh queue << 'EOF'
["printenv", "setenv bootcmd run bootusb", "saveenv", "boot"]
EOF
```

### Build Eye Remote Image

```bash
cd remote-ui/round

# Full installation
sudo ./install_zerow.sh \
    -d /dev/sdX \
    -i 2024-11-19-raspios-bookworm-armhf-lite.img.xz \
    -s "YourWiFi" \
    -p "YourPassword" \
    -k ~/.ssh/id_rsa.pub \
    -r \
    --kiosk
```

### Service Management

| Service | Description | Port |
|---------|-------------|------|
| `secubox-otg-gadget.service` | USB gadget manager | - |
| `secubox-remote-ui.service` | Nginx + dashboard | 8080 |
| `secubox-serial-console.service` | Serial on ttyGS0 | 115200 |
| `secubox-eye-agent.service` | Metrics bridge | - |

---

## Quick Reference

### Network

| Interface | IP | Purpose |
|-----------|----|---------|
| usb0 (Eye Remote) | 10.55.0.2/30 | OTG network |
| secubox-round (Host) | 10.55.0.1/30 | SecuBox side |

### Default Credentials

| Service | User | Password |
|---------|------|----------|
| SSH | pi | raspberry (change!) |
| Dashboard API | dashboard | secubox-round |

### Common Commands

```bash
# Check gadget status
ssh pi@10.55.0.2 "systemctl status secubox-otg-gadget"

# View dashboard logs
ssh pi@10.55.0.2 "journalctl -u secubox-remote-ui -f"

# Test API connection
curl http://10.55.0.1:8000/api/v1/health

# Switch to debug mode
ssh pi@10.55.0.2 "sudo secubox-otg-gadget.sh debug"
```

---

## See Also

- [[Eye-Remote]] — Overview
- [[Eye-Remote-Hardware]] — GPIO, display configuration
- [[Eye-Remote-Bootstrap]] — Boot media details
- [[Eye-Remote-Implementation]] — Software architecture

---

*SecuBox Eye Remote Multigadget System*
*CyberMind — https://cybermind.fr*
