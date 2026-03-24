# SecuBox Debian - UI Documentation

*CRT P31 phosphor theme documentation*

## About SecuBox Debian

SecuBox Debian is the next-generation security appliance running on Debian Bookworm with a modern FastAPI backend.

**Repository:** [secubox-deb](https://github.com/CyberMind-FR/secubox-deb)

## UI Theme: CRT P31 Phosphor

The Debian version features a retro CRT terminal aesthetic inspired by P31 phosphor green monitors:

```css
:root {
    /* P31 Phosphor Green Palette */
    --p31-peak: #33ff66;    /* Bright phosphor green */
    --p31-hot: #66ffaa;     /* Hot phosphor glow */
    --p31-mid: #22cc44;     /* Standard text */
    --p31-dim: #0f8822;     /* Dim text */
    --p31-ghost: #052210;   /* Ghost/borders */

    /* Decay (Warnings/Errors) */
    --p31-decay: #ffb347;   /* Amber decay */
    --p31-decay-dim: #cc7722;

    /* CRT Tube Colors */
    --tube-black: #050803;  /* CRT black */
    --tube-deep: #080d05;   /* Deep background */
    --tube-bezel: #0d1208;  /* Bezel color */

    /* Legacy Mappings */
    --bg-dark: var(--tube-black);
    --bg-card: var(--tube-deep);
    --border: var(--p31-ghost);
    --text: var(--p31-mid);
    --text-dim: var(--p31-dim);
    --primary: var(--p31-peak);
    --cyan: var(--p31-peak);
    --green: var(--p31-peak);
    --red: var(--p31-decay);
    --yellow: var(--p31-decay);

    /* Glow Effects */
    --bloom-text: 0 0 2px var(--p31-peak), 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
    --bloom-soft: 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
}
```

### Theme Features

- **Phosphor glow effects** - Text shadow with bloom effect
- **Scanline overlay** - Optional CRT scanline effect
- **Monospace fonts** - Courier Prime for terminal aesthetic
- **Amber warnings** - P31 decay color for alerts
- **Responsive design** - Collapsible sidebar on mobile

### Shared CSS Files

| File | Purpose |
|------|---------|
| `/shared/crt-system.css` | Full CRT styling, animations, effects |
| `/shared/sidebar.css` | Navigation sidebar styles |
| `/shared/sidebar.js` | Dynamic menu loading |

## Architecture

### Backend Stack

```
┌─────────────────────────────────────────────┐
│                  Nginx                       │
│         (Reverse Proxy + Static)            │
├─────────────────────────────────────────────┤
│     /api/v1/<module>/  →  Unix Socket       │
│     /static/           →  /var/www/         │
├─────────────────────────────────────────────┤
│              FastAPI + Uvicorn              │
│         (Per-module Python service)         │
├─────────────────────────────────────────────┤
│              secubox_core                    │
│        (Shared: auth, config, logger)       │
├─────────────────────────────────────────────┤
│           System Services                    │
│   (CrowdSec, WireGuard, nftables, etc.)     │
└─────────────────────────────────────────────┘
```

### Frontend Stack

- **Vanilla JS** - No framework dependencies
- **CSS Variables** - Themeable design system
- **Fetch API** - REST client with JWT
- **WebSocket** - Real-time updates (SOC)
- **LocalStorage** - Token persistence

### Authentication Flow

```
1. User → /portal/login.html
2. Submit credentials → POST /api/v1/portal/login
3. Receive JWT token → localStorage.setItem('sbx_token', token)
4. API calls include → Authorization: Bearer <token>
5. Token expires → Redirect to login
```

## Module Categories

| Category | Modules | Description |
|----------|---------|-------------|
| Dashboard | 3 | Hub, SOC, Roadmap |
| Security | 5 | CrowdSec, WAF, Vortex Firewall, Hardening, MITM |
| Network | 6 | Netmodes, QoS, Traffic, HAProxy, CDN, VHost |
| DNS | 3 | DNS, Vortex DNS, Meshname |
| VPN | 3 | WireGuard, Mesh, P2P |
| Privacy | 3 | Tor, Exposure, ZKP |
| Monitoring | 5 | Netdata, DPI, Device Intel, Watchdog, MediaFlow |
| Access | 4 | Auth, NAC, Users, Portal |
| Services | 3 | C3Box, Gitea, Nextcloud |
| Email | 2 | Mail, Webmail |
| Publishing | 3 | Publish, Droplet, Metablogizer |
| Apps | 3 | Streamlit, StreamForge, Repo |
| System | 2 | System, Backup |
| **Total** | **47** | |

## API Documentation

### Common Patterns

```bash
# Get module status
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://secubox/api/v1/<module>/status

# List items
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://secubox/api/v1/<module>/list

# Create item
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "value"}' \
    https://secubox/api/v1/<module>/create

# Delete item
curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" \
    https://secubox/api/v1/<module>/delete/<id>
```

### Example: SOC API

```bash
# World clock
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://secubox/api/v1/soc/clock

# Threat map
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://secubox/api/v1/soc/map/threats

# Create ticket
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"title": "Suspicious Activity", "severity": "high"}' \
    https://secubox/api/v1/soc/tickets

# WebSocket for real-time
wscat -c wss://secubox/api/v1/soc/ws \
    -H "Authorization: Bearer $TOKEN"
```

## Deployment

### Supported Platforms

| Board | SoC | Arch | Profile |
|-------|-----|------|---------|
| MOCHAbin | Armada 7040 | arm64 | secubox-full |
| ESPRESSObin v7 | Armada 3720 | arm64 | secubox-lite |
| ESPRESSObin Ultra | Armada 3720 | arm64 | secubox-lite |
| VirtualBox VM | x86_64 | amd64 | secubox-full |

### Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install full suite
sudo apt install secubox-full

# Or lite version
sudo apt install secubox-lite
```

## Screenshots

See [Module Gallery](screenshots/) for UI screenshots.

To capture screenshots:

```bash
# Install dependencies
pip install -r scripts/requirements-screenshot.txt
playwright install chromium

# Capture from VM
python3 scripts/screenshot-tool.py --host vm

# Capture from device
python3 scripts/screenshot-tool.py --host device

# Compare both
python3 scripts/screenshot-tool.py --compare --all
```

---

*Generated by SecuBox Screenshot Tool*
