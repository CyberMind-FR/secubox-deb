# Architecture — Modules

SecuBox OS modular architecture with 125 packages.

---

## Module Stacks

SecuBox organizes modules into 6 functional stacks:

| Stack | Color | Function | Key Modules |
|-------|-------|----------|-------------|
| 🟠 AUTH | Orange | Authentication | auth, portal, nac, users |
| 🟡 WALL | Yellow | Security | crowdsec, waf, ipblock, threats |
| 🔴 BOOT | Red | Deployment | cloner, vault, vm, backup |
| 🟣 MIND | Purple | Intelligence | dpi, ai-insights, netdata |
| 🟢 ROOT | Green | System | core, hub, system, admin |
| 🔵 MESH | Blue | Network | wireguard, haproxy, qos, mesh |

---

## Package Naming

All packages follow the pattern: `secubox-<module>`

```
secubox-core        # Core library (required)
secubox-hub         # Central dashboard
secubox-crowdsec    # CrowdSec IDS
secubox-wireguard   # WireGuard VPN
...
```

---

## Module Structure

Each module follows a standard structure:

```
packages/secubox-<module>/
├── api/
│   └── main.py           # FastAPI endpoints
├── www/
│   ├── index.html        # Web UI
│   └── assets/           # CSS, JS, images
├── debian/
│   ├── control           # Package metadata
│   ├── postinst          # Post-install script
│   └── secubox-<module>.service
└── README.md
```

---

## API Pattern

All modules expose REST APIs via Unix socket:

```
Socket: /run/secubox/<module>.sock
Nginx:  /api/v1/<module>/* → unix:/run/secubox/<module>.sock
```

### Endpoint Convention

| RPCD (OpenWrt) | FastAPI (SecuBox) |
|----------------|-------------------|
| `luci.module/get_status` | `GET /api/v1/module/status` |
| `luci.module/set_config` | `POST /api/v1/module/config` |
| `luci.module/apply` | `POST /api/v1/module/apply` |

---

## Dependencies

```
secubox-core (required by all)
    ├── secubox-hub
    ├── secubox-system
    └── secubox-* (all modules)
```

### Install Order

1. `secubox-core` — Base library
2. `secubox-hub` — Dashboard
3. Other modules (any order)

---

## Module Communication

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   nginx     │────►│  FastAPI    │────►│  Backend    │
│  :443/9443  │     │  Unix sock  │     │  Service    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │
       │              JWT Auth
       │                   │
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│   Web UI    │     │ secubox-core│
│   Browser   │     │   Library   │
└─────────────┘     └─────────────┘
```

---

## Creating New Modules

```bash
# Scaffold new module
bash scripts/new-module.sh mymodule

# Build package
cd packages/secubox-mymodule
dpkg-buildpackage -us -uc -b

# Install
sudo dpkg -i ../secubox-mymodule_*.deb
```

See [[Developer-Guide]] for details.

---

*← Back to [[Home|SecuBox OS]]*
