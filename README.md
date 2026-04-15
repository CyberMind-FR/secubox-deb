# SecuBox

**Your Network Security Appliance — Plug, Protect, Peace of Mind**

[![Build Status](https://github.com/CyberMind-FR/secubox-deb/actions/workflows/build-all-live-usb.yml/badge.svg)](https://github.com/CyberMind-FR/secubox-deb/actions)
[![Version](https://img.shields.io/badge/version-1.7.0-green.svg)](https://github.com/CyberMind-FR/secubox-deb/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

SecuBox transforms any compatible device into a complete network security appliance with VPN, firewall, intrusion detection, and web dashboard — all preconfigured and ready to use.

---

## What You Get

- **VPN Server** — WireGuard with QR codes for mobile devices
- **Intrusion Detection** — CrowdSec IDS/IPS with automatic threat blocking
- **Network Monitoring** — Real-time traffic analysis and bandwidth control
- **Web Dashboard** — Modern dark-themed interface accessible from any browser
- **Automatic Updates** — Security patches applied automatically

---

## Quick Start

### Option 1: VirtualBox (Try It Now)

Download and run in VirtualBox — no hardware required:

```bash
# Download the image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# Extract
gunzip secubox-live-amd64-bookworm.img.gz

# Create VM (requires VBoxManage)
./scripts/create-secubox-vm.sh secubox-live-amd64-bookworm.img
```

**Access:** Open https://localhost:9443 in your browser
**Login:** `admin` / `secubox`

### Option 2: Live USB (Any PC)

Boot from USB on any x86_64 computer:

```bash
# Download
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# Flash to USB (replace /dev/sdX with your USB device)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Boot from USB, then access the dashboard at `https://<device-ip>/`

### Option 3: Dedicated Hardware

For 24/7 operation, flash to dedicated hardware:

| Device | Best For | Image |
|--------|----------|-------|
| Raspberry Pi 4/5 | Home use | `secubox-rpi-arm64-*.img.gz` |
| ESPRESSObin | Small office | `secubox-espressobin-v7-*.img.gz` |
| MOCHAbin | Enterprise | `secubox-mochabin-*.img.gz` |
| Any x86_64 PC | Repurposed hardware | `secubox-live-amd64-*.img.gz` |

---

## Features

### Security Dashboard
Central control panel showing system health, active threats, and quick actions.

### VPN (WireGuard)
Create VPN connections with one click. Scan QR codes on mobile devices.

### Intrusion Detection (CrowdSec)
Automatic threat detection and IP blocking with community threat intelligence.

### Network Control
- Bandwidth management (QoS)
- Device access control
- Deep packet inspection
- Virtual hosts with SSL

### System Management
- Service control
- Log viewer
- Automatic backups
- Easy updates

---

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web Dashboard | `admin` | `secubox` |
| SSH | `root` | `secubox` |

**Change these immediately after first login!**

---

## Support

- **Wiki:** [github.com/CyberMind-FR/secubox-deb/wiki](https://github.com/CyberMind-FR/secubox-deb/wiki)
- **Issues:** [github.com/CyberMind-FR/secubox-deb/issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- **Email:** support@secubox.in

---

## License

Apache-2.0 © 2026 [CyberMind](https://cybermind.fr) · Gérald Kerma

---

<details>
<summary><h2>Technical Reference (Click to Expand)</h2></summary>

### Architecture

```
OpenWrt / LuCI                   →    Debian bookworm
─────────────────────────────────────────────────────────
RPCD shell backend               →    FastAPI + Uvicorn (Unix socket)
UCI config /etc/config/          →    TOML /etc/secubox/secubox.conf
luci-app-*/htdocs/ (JS/CSS/HTML) →    Conservé + XHR réécrits
OpenWrt packages (.ipk)          →    Paquets Debian (.deb)
opkg                             →    apt + repo apt.secubox.in
```

### Supported Hardware

| Board | SoC | RAM | Network | Profile |
|-------|-----|-----|---------|---------|
| MOCHAbin | Armada 7040 Quad 1.8GHz | 4 GB | 2× SFP+ 10GbE + 4× GbE | Pro |
| ESPRESSObin v7 | Armada 3720 Dual 1.2GHz | 1–2 GB | WAN + 2× LAN DSA | Lite |
| ESPRESSObin Ultra | Armada 3720 Dual 1.2GHz | 2 GB | WAN PoE + 4× LAN + Wi-Fi | Lite+ |
| Raspberry Pi 4/400 | BCM2711 Quad 1.5-1.8GHz | 2-8 GB | GbE + USB | Lite |
| Raspberry Pi 5 | BCM2712 Quad 2.4GHz | 4-8 GB | GbE + USB | Full |
| VM x86_64 | Any | 2+ GB | Virtio/NAT | Full |

### Packages (126 modules)

**Core:** secubox-core, secubox-hub, secubox-portal, secubox-system

**Security:** secubox-crowdsec, secubox-wireguard, secubox-auth, secubox-nac, secubox-waf, secubox-users

**Network:** secubox-netmodes, secubox-dpi, secubox-qos, secubox-vhost, secubox-haproxy

**Monitoring:** secubox-netdata, secubox-mediaflow, secubox-cdn

**DNS/Email:** secubox-dns, secubox-mail, secubox-webmail

**Publishing:** secubox-droplet, secubox-streamlit, secubox-metablogizer, secubox-publish

### API Reference

All modules expose REST APIs at `/api/v1/<module>/`

```bash
# Login
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secubox"}'

# Use token
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

**Key Endpoints:**
- `GET /api/v1/hub/dashboard` — Dashboard data
- `GET /api/v1/crowdsec/decisions` — Active bans
- `POST /api/v1/crowdsec/ban` — Ban IP
- `GET /api/v1/wireguard/peers` — VPN peers
- `GET /api/v1/wireguard/qrcode/{peer}` — Peer QR code

### Configuration

Main config: `/etc/secubox/secubox.conf` (TOML)

```toml
[general]
hostname = "secubox"
timezone = "Europe/Paris"

[auth]
jwt_secret = "your-secret-key"
session_timeout = 86400

[network]
wan_interface = "eth0"
lan_interface = "eth1"
```

### Development

```bash
# Setup
bash setup-dev.sh && source .venv/bin/activate

# Run module API
cd packages/secubox-crowdsec
uvicorn api.main:app --reload --port 8001

# Build package
dpkg-buildpackage -us -uc -b

# Build image
sudo bash image/build-image.sh --board vm-x64 --vdi
```

### UI Design Guidelines

**Color Palette (Cyberpunk/Hermetic):**

| Variable | Color | Usage |
|----------|-------|-------|
| `--cosmos-black` | `#0a0a0f` | Background |
| `--gold-hermetic` | `#c9a84c` | Accents, titles |
| `--cinnabar` | `#e63946` | Alerts, errors |
| `--matrix-green` | `#00ff41` | Success |
| `--void-purple` | `#6e40c9` | Links |
| `--cyber-cyan` | `#00d4ff` | Info, hover |
| `--text-primary` | `#e8e6d9` | Main text |

**Typography:** Cinzel (titles), IM Fell English (body), JetBrains Mono (code)

### Documentation

- [Live USB Guide](docs/LIVE-USB.md)
- [User Guide](docs/USER-GUIDE.md)
- [API Reference](docs/API-REFERENCE.md)
- [Migration Map](.claude/MIGRATION-MAP.md)
- [Developer Guide](CLAUDE.md)

</details>
