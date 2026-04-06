# SecuBox UI Comparison: OpenWRT vs Debian

*Side-by-side comparison of the two SecuBox implementations*

## Overview

| Aspect | OpenWRT | Debian |
|--------|---------|--------|
| **Repository** | [secubox-openwrt](https://github.com/gkerma/secubox-openwrt) | [secubox-deb](https://github.com/CyberMind-FR/secubox-deb) |
| **Base OS** | OpenWRT 23.05+ | Debian Bookworm |
| **Architecture** | mipsel, arm | arm64, amd64 |
| **Target Hardware** | Routers, embedded | GlobalScale boards, VMs |
| **Module Count** | 17 | 47 |
| **Theme** | LuCI Dark | CRT P31 Phosphor |

## Visual Comparison

### Theme

| OpenWRT LuCI | Debian CRT P31 |
|--------------|----------------|
| Dark blue/gray | Phosphor green |
| Sans-serif fonts | Monospace (Courier) |
| Flat design | Glow effects |
| Standard buttons | Terminal aesthetic |

### Dashboard

| OpenWRT | Debian |
|---------|--------|
| System overview widget | Real-time metrics |
| Network status | Service status grid |
| Package info | Module health |
| Basic graphs | Animated charts |

### Navigation

| OpenWRT | Debian |
|---------|--------|
| Top menu bar | Collapsible sidebar |
| Dropdown submenus | Icon + text links |
| Category tabs | Category groups |
| Breadcrumbs | Module header |

## Technical Comparison

### Backend

| Component | OpenWRT | Debian |
|-----------|---------|--------|
| Web Framework | LuCI (Lua) | FastAPI (Python) |
| IPC | ubus + RPCD | Unix sockets |
| Config Format | UCI | TOML |
| Auth | Session cookies | JWT tokens |
| API Style | RPC | REST |

### Frontend

| Component | OpenWRT | Debian |
|-----------|---------|--------|
| Templating | Lua views | Vanilla JS |
| Styling | LESS/CSS | CSS Variables |
| JS Framework | LuCI.js | None (vanilla) |
| Real-time | Polling | WebSocket |

### Services

| Service | OpenWRT | Debian |
|---------|---------|--------|
| CrowdSec | ✅ | ✅ |
| WireGuard | ✅ | ✅ |
| nftables | ✅ | ✅ |
| HAProxy | ✅ | ✅ |
| Netdata | ✅ | ✅ |
| LXC | ❌ | ✅ |
| AppArmor | ❌ | ✅ |
| Audit | ❌ | ✅ |
| SOC | ❌ | ✅ |

## Module Mapping

### Core Modules (Ported)

| OpenWRT Package | Debian Package | Status |
|-----------------|----------------|--------|
| luci-app-secubox | secubox-hub | ✅ Complete |
| luci-app-crowdsec-dashboard | secubox-crowdsec | ✅ Complete |
| luci-app-wireguard-dashboard | secubox-wireguard | ✅ Complete |
| luci-app-auth-guardian | secubox-auth | ✅ Complete |
| luci-app-client-guardian | secubox-nac | ✅ Complete |
| luci-app-network-modes | secubox-netmodes | ✅ Complete |
| luci-app-netifyd-dashboard | secubox-dpi | ✅ Complete |
| luci-app-bandwidth-manager | secubox-qos | ✅ Complete |
| luci-app-vhost-manager | secubox-vhost | ✅ Complete |
| luci-app-cdn-cache | secubox-cdn | ✅ Complete |
| luci-app-netdata-dashboard | secubox-netdata | ✅ Complete |
| luci-app-media-flow | secubox-mediaflow | ✅ Complete |
| luci-app-system-hub | secubox-system | ✅ Complete |
| luci-app-droplet | secubox-droplet | ✅ Complete |
| luci-app-metablogizer | secubox-metablogizer | ✅ Complete |
| luci-app-streamlit | secubox-streamlit | ✅ Complete |
| luci-app-streamlit-forge | secubox-streamforge | ✅ Complete |

### New Debian-Only Modules

| Package | Description |
|---------|-------------|
| secubox-portal | Login/auth portal |
| secubox-waf | Web Application Firewall |
| secubox-hardening | System hardening |
| secubox-dns | BIND DNS server |
| secubox-mail | Postfix/Dovecot mail |
| secubox-webmail | Roundcube/SOGo |
| secubox-users | Identity management |
| secubox-publish | Unified publishing |
| secubox-gitea | Git server (LXC) |
| secubox-nextcloud | File sync (LXC) |
| secubox-c3box | Services portal |
| secubox-tor | Tor network |
| secubox-exposure | Exposure settings |
| secubox-mitmproxy | MITM inspection |
| secubox-backup | System backup |
| secubox-watchdog | Service monitor |
| secubox-traffic | Traffic shaping |
| secubox-device-intel | Asset discovery |
| secubox-vortex-dns | DNS firewall |
| secubox-vortex-firewall | Threat firewall |
| secubox-meshname | Mesh DNS |
| secubox-mesh | Mesh network |
| secubox-p2p | P2P network |
| secubox-zkp | Zero-knowledge |
| secubox-soc | Security Operations |
| secubox-roadmap | Migration tracker |
| secubox-repo | APT repository |

## Performance Comparison

| Metric | OpenWRT | Debian |
|--------|---------|--------|
| RAM Usage | ~128MB | ~512MB |
| Disk Usage | ~64MB | ~2GB |
| Boot Time | ~30s | ~45s |
| API Latency | ~50ms | ~20ms |
| Concurrent Users | ~10 | ~100 |

*Note: Debian requires more resources but provides better performance and scalability.*

## Migration Path

1. **Export OpenWRT config** - UCI settings
2. **Install Debian image** - Flash to device or VM
3. **Import settings** - Convert UCI → TOML
4. **Install packages** - `apt install secubox-full`
5. **Verify services** - Check all APIs responding
6. **Update clients** - Point to new IP if changed

## Screenshots

### To Capture

Use the screenshot tool to capture both environments:

```bash
# From the secubox-deb repository
cd /path/to/secubox-deb

# Install dependencies
pip install -r scripts/requirements-screenshot.txt
playwright install chromium

# Capture VM screenshots
python3 scripts/screenshot-tool.py --host vm

# Capture device screenshots
python3 scripts/screenshot-tool.py --host device

# Generate comparison
python3 scripts/screenshot-tool.py --compare --all
```

Screenshots will be saved to:
- `docs/screenshots/vm/` - VM screenshots
- `docs/screenshots/device/` - Device screenshots
- `docs/SCREENSHOTS-VM.md` - VM gallery
- `docs/SCREENSHOTS-DEVICE.md` - Device gallery
- `docs/UI-COMPARISON.md` - Side-by-side comparison

---

*Generated by SecuBox Documentation Tool*
