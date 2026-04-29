# Eye Remote OTG Features Plan

## Overview

Extend Eye Remote Round UI (Pi Zero W + HyperPixel 2.1 Round) with OTG management, real metrics display, and SecuBox self-setup capabilities.

## Feature 1: OTG Tools Dashboard ✅

**Status:** Implemented (2026-04-28)

**Purpose:** Display USB gadget status and connected host information

### Components
- `remote-ui/round/agent/display/gadget_status.py` — Gadget mode renderer
- `remote-ui/round/agent/api/gadget.py` — Gadget control API

### Display Elements
- Current gadget mode icon (ECM/ACM/Mass Storage/Composite)
- Connection status (Host connected / Disconnected)
- Host IP (when ECM connected)
- Data transfer indicator (RX/TX activity)

### Implementation
```python
# Gadget modes with icons
GADGET_MODES = {
    'ecm': {'icon': '🌐', 'name': 'Network'},
    'acm': {'icon': '📟', 'name': 'Serial'},
    'mass_storage': {'icon': '💾', 'name': 'Storage'},
    'composite': {'icon': '🔗', 'name': 'Composite'}
}
```

---

## Feature 2: Real Metrics Display ✅

**Status:** Implemented (2026-04-28)

**Purpose:** Show actual metrics from connected SecuBox (not simulated)

### Data Sources
- **OTG ECM (10.55.0.1):** Fetch via HTTP API from SecuBox
- **WiFi (secubox.local):** Same API, different transport
- **Offline:** Show local Pi Zero metrics only

### Metrics to Display
| Ring | Metric | Source |
|------|--------|--------|
| AUTH | Active sessions / Failed logins | `/api/v1/auth/stats` |
| WALL | Blocked IPs / WAF events | `/api/v1/crowdsec/metrics` |
| BOOT | Uptime / Boot count | `/api/v1/system/status` |
| MIND | CPU / RAM usage | `/api/v1/system/metrics` |
| ROOT | Disk usage / IO | `/api/v1/system/storage` |
| MESH | WireGuard peers / Traffic | `/api/v1/wireguard/status` |

### Implementation
- Modify `fallback_manager.py` to fetch real metrics
- Cache metrics with 5-second refresh
- Graceful fallback to simulated data if API unavailable

---

## Feature 3: Gadget Parameters & Mode Control ✅

**Status:** Implemented (2026-04-28)

**Purpose:** Switch USB gadget modes and configure parameters

### Modes
1. **ECM (Ethernet)** — Network connection to host
2. **ACM (Serial)** — Serial console access
3. **Mass Storage** — Expose storage partition
4. **Composite** — ECM + ACM + Storage combined

### Control Methods
- Touch gesture on display (swipe pattern)
- API endpoint for remote control
- Auto-switch based on context

### Configuration File
```toml
# /etc/secubox/eye-remote/gadget.toml
[gadget]
default_mode = "composite"
auto_switch = true

[ecm]
host_ip = "10.55.0.1"
device_ip = "10.55.0.2"
netmask = "255.255.255.252"

[mass_storage]
partition = "/dev/mmcblk0p3"
readonly = false

[acm]
baudrate = 115200
```

### API Endpoints
```
POST /api/v1/eye-remote/gadget/mode
  body: {"mode": "ecm|acm|mass_storage|composite"}

GET /api/v1/eye-remote/gadget/status
  returns: {"mode": "composite", "host_connected": true, "host_ip": "10.55.0.1"}
```

---

## Feature 4: Storage Sync for Configs & Backup ✅

**Status:** Implemented (2026-04-28)

**Purpose:** Use mass_storage gadget to sync confidential data and backup configs

### Storage Layout
```
/srv/eye-remote/storage/     (mounted as mass_storage)
├── configs/
│   ├── secubox/             ← SecuBox config exports
│   ├── wireguard/           ← WireGuard keys (encrypted)
│   └── credentials/         ← Encrypted credentials vault
├── backups/
│   ├── 2026-04-28/          ← Dated backups
│   └── latest -> 2026-04-28
├── firmware/
│   └── secubox-*.img.gz     ← Firmware images for flashing
└── logs/
    └── audit/               ← Security audit logs
```

### Sync Operations
1. **Export Config** — SecuBox → Eye Remote storage
2. **Import Config** — Eye Remote storage → SecuBox
3. **Backup** — Full config snapshot with encryption
4. **Restore** — Restore from backup

### Security
- AES-256 encryption for sensitive files
- GPG signing for integrity
- Audit log of all sync operations

### API Endpoints
```
POST /api/v1/eye-remote/storage/export
  body: {"target": "secubox", "modules": ["wireguard", "crowdsec"]}

POST /api/v1/eye-remote/storage/import
  body: {"source": "configs/secubox/", "validate": true}

POST /api/v1/eye-remote/storage/backup
  body: {"name": "pre-upgrade", "encrypt": true}

POST /api/v1/eye-remote/storage/restore
  body: {"backup": "2026-04-28", "modules": ["all"]}
```

---

## Feature 5: Self-Setup Portal ✅

**Status:** Implemented (2026-04-28)

**Purpose:** Guide new SecuBox setup through Eye Remote interface

### Setup Wizard Steps

1. **Welcome** — Detect connected SecuBox, show model info
2. **Network** — Configure WAN/LAN interfaces
3. **Security** — Set admin password, generate TLS cert
4. **Services** — Enable/disable modules (CrowdSec, WireGuard, DPI)
5. **Mesh** — Join MirrorNet or standalone mode
6. **Verify** — Test connectivity, show dashboard preview
7. **Complete** — Reboot into production mode

### Display Flow
```
[Splash: Phoenix logo]
      ↓
[Detect: "SecuBox Found"]
      ↓
[Step 1-7: Wizard screens]
      ↓
[Complete: Checkmark + "Ready"]
      ↓
[Dashboard: Normal operation]
```

### Touch Interactions
- **Tap center** — Confirm / Next
- **Swipe left** — Back
- **Swipe right** — Skip (where allowed)
- **Long press** — Cancel / Exit wizard

### API Integration
```
POST /api/v1/eye-remote/setup/start
GET /api/v1/eye-remote/setup/status
POST /api/v1/eye-remote/setup/step/{n}
POST /api/v1/eye-remote/setup/complete
```

---

## Implementation Order

| Phase | Feature | Priority | Complexity | Status |
|-------|---------|----------|------------|--------|
| 1 | Real Metrics Display | High | Low | ✅ Done |
| 2 | OTG Tools Dashboard | High | Medium | ✅ Done |
| 3 | Gadget Mode Control | Medium | Medium | ✅ Done |
| 4 | Storage Sync | Medium | High | ✅ Done |
| 5 | Self-Setup Portal | Low | High | ✅ Done |

## Files to Create/Modify

### New Files (All Created ✅)
- `remote-ui/round/agent/api/gadget.py` ✅
- `remote-ui/round/agent/api/gadget_config.py` ✅
- `remote-ui/round/agent/api/gadget_switcher.py` ✅
- `remote-ui/round/agent/api/setup.py` ✅
- `remote-ui/round/agent/display/gadget_status.py` ✅
- `remote-ui/round/agent/display/gadget_gesture.py` ✅
- `remote-ui/round/agent/display/setup_wizard.py` ✅
- `remote-ui/round/agent/sync/storage_manager.py` ✅
- `remote-ui/round/agent/sync/backup_manager.py` ✅
- `remote-ui/round/agent/sync/config_sync.py` ✅
- `remote-ui/round/agent/web/routes/gadget.py` ✅
- `remote-ui/round/agent/web/routes/storage.py` ✅
- `remote-ui/round/agent/web/routes/setup.py` ✅
- `remote-ui/round/config/gadget.toml` ✅
- `remote-ui/round/scripts/eye-gadget-switch.sh` ✅

### Modified Files
- `remote-ui/round/agent/display/fallback/fallback_manager.py` — Real metrics
- `remote-ui/round/agent/display/display_manager.py` — New display modes
- `remote-ui/round/agent/main.py` — New API routes
- `remote-ui/round/config/gadget.toml` — Gadget configuration

## Dependencies

- `aiohttp` — Async HTTP client for API calls
- `cryptography` — AES encryption for backups
- `python-gnupg` — GPG signing (optional)

---

## Completion Status

All 5 features have been implemented:

1. ✅ Real Metrics Display — Async metrics fetching from SecuBox API
2. ✅ OTG Tools Dashboard — Gadget status bar and connection indicators
3. ✅ Gadget Mode Control — Mode switching via configfs with gesture support
4. ✅ Storage Sync — Encrypted backup/restore with config synchronization
5. ✅ Self-Setup Portal — 7-step wizard for new SecuBox configuration

### API Endpoints Added

| Prefix | Routes |
|--------|--------|
| `/gadget` | `/status`, `/mode`, `/modes`, `/config` |
| `/storage` | `/info`, `/mount`, `/files`, `/backup`, `/export`, `/import` |
| `/setup` | `/status`, `/start`, `/next`, `/back`, `/detect`, `/verify`, `/complete` |

---

*Created: 2026-04-28*
*Completed: 2026-04-28*
*Author: Claude Code*
