<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Skill: /multigadget - Eye Remote USB Gadget System

Reference documentation and development guide for the SecuBox Eye Remote multi-mode USB gadget system.

## Usage

```
/multigadget [topic]
```

Topics: `autorun` | `storage` | `roundui` | `tooling` | `all`

## What This Skill Covers

### 1. Autorun System

USB gadget initialization and mode switching:

| Mode | Gadget Functions | Use Case |
|------|------------------|----------|
| **Normal** | ECM + ACM | Dashboard + serial console |
| **Flash** | Mass Storage | Boot recovery image |
| **Debug** | ECM + ACM + Mass Storage | Export logs |
| **TTY** | HID Keyboard + ACM | U-Boot automation |
| **Auth** | FIDO2 HID | Hardware 2FA |

**Key files:**
- `remote-ui/round/secubox-otg-gadget.sh` — configfs gadget setup
- `remote-ui/round/secubox-otg-gadget.service` — systemd autostart
- `/sys/kernel/config/usb_gadget/secubox/` — runtime config

**Boot sequence:**
```
1. dwc2 module loads (dr_mode=peripheral)
2. libcomposite module loads
3. secubox-otg-gadget.service starts
4. configfs gadget created with ECM + ACM
5. Network 10.55.0.2 comes up on usb0
6. Dashboard connects to SecuBox at 10.55.0.1
```

### 2. Guest/Host Storage Rebound

Double-buffer boot media with atomic swap and 4R rollback:

```
/var/cache/secubox/boot-media/
├── active/          ← Live boot media (read-only in prod)
│   ├── KERNEL
│   ├── INITRD
│   ├── DTB
│   └── metadata.json
├── shadow/          ← Staging area for updates
│   └── pending_swap.flag
└── rollback/        ← 4 generations
    ├── R1/
    ├── R2/
    ├── R3/
    └── R4/
```

**Swap protocol:**
1. Validate `SHA256(shadow/KERNEL)` matches expected
2. `fsync()` all shadow files
3. Atomic rename: `shadow → active` (via `mv -T`)
4. Archive old active: `active → R1`, shift R1→R2→R3→R4
5. Clear `pending_swap.flag`

**API endpoints:**
- `GET /api/v1/eye-remote/boot-media/state`
- `POST /api/v1/eye-remote/boot-media/upload`
- `POST /api/v1/eye-remote/boot-media/swap`
- `POST /api/v1/eye-remote/boot-media/rollback`

### 3. Round UI Dashboard

480×480 circular display with 6-ring status visualization:

| Ring | Module | Metric | Color |
|------|--------|--------|-------|
| Outer | AUTH | CPU % | #C04E24 |
| 2 | WALL | MEM % | #9A6010 |
| 3 | BOOT | DISK % | #803018 |
| 4 | MIND | LOAD | #3D35A0 |
| 5 | ROOT | TEMP °C | #0A5840 |
| Inner | MESH | WiFi dBm | #104A88 |

**Key files:**
- `remote-ui/round/index.html` — Main dashboard (124KB, zero CDN)
- `remote-ui/round/agent/` — Python backend agent
- `remote-ui/round/assets/icons/` — 24 PNG icons (6 modules × 4 sizes)

**Radial menu (long-press center):**
- DEVICES → Scan, Pair, Forget
- SECUBOX → Status, Modules, Logs, Restart
- LOCAL → Display, Network, System, About
- NETWORK → Interfaces, Routes, DNS, Firewall
- SECURITY → Alerts, Bans, Rules, Audit
- EXIT → Dashboard, Sleep, Reboot, Shutdown

### 4. CyberMind Tooling

Development and deployment scripts:

| Script | Purpose |
|--------|---------|
| `install_zerow.sh` | Flash Pi Zero W SD card with OTG config |
| `deploy.sh` | Deploy dashboard to Eye Remote via SSH |
| `prep_zerow_hyperpixel.sh` | Configure HyperPixel 2.1 Round display |
| `secubox-hid-keyboard.sh` | Send keystrokes via HID gadget |

**Deploy example:**
```bash
./deploy.sh \
    -h secubox-round.local \
    --api-url http://10.55.0.1:8000 \
    --api-pass "YourAPIPassword"
```

## Reference Files

| Category | Path |
|----------|------|
| Wiki | `docs/wiki/Eye-Remote-Multigadget.md` |
| Main CLAUDE.md | `remote-ui/round/CLAUDE.md` |
| Roadmap | `remote-ui/round/ROADMAP.md` |
| API | `packages/secubox-eye-remote/api/` |
| Services | `remote-ui/round/systemd/` |

## Quick Commands

```bash
# Switch gadget mode
ssh pi@10.55.0.2 "sudo secubox-otg-gadget.sh tty"

# Send U-Boot command
./secubox-hid-keyboard.sh cmd 'printenv'

# Check boot media state
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state

# Deploy dashboard
./remote-ui/round/deploy.sh -h 10.55.0.2 --no-sim

# Test radial menu
python remote-ui/round/test-dashboard-amd64.py
```

## Languages

Documentation available in:
- English: `Eye-Remote-Multigadget.md`
- French: `Eye-Remote-Multigadget-FR.md`
- Chinese: `Eye-Remote-Multigadget-ZH.md`
