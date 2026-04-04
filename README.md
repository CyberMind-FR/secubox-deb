# SecuBox-DEB

## Migration OpenWrt → Debian · GlobalScale Technologies
**CyberMind · Gandalf · Mars 2026**

Port complet de [SecuBox OpenWrt](https://github.com/gkerma/secubox-openwrt) vers **Debian bookworm arm64/amd64** pour les boards **MOCHAbin** (Armada 7040), **ESPRESSObin** (Armada 3720), et **VMs x86_64**.

---

## Architecture

```
OpenWrt / LuCI                   →    Debian bookworm
─────────────────────────────────────────────────────────
RPCD shell backend               →    FastAPI + Uvicorn (Unix socket)
UCI config /etc/config/          →    TOML /etc/secubox/secubox.conf
luci-app-*/htdocs/ (JS/CSS/HTML) →    Conservé + XHR réécrits
OpenWrt packages (.ipk)          →    Paquets Debian (.deb)
opkg                             →    apt + repo apt.secubox.in
```

**Boards supportés :**

| Board | SoC | RAM | Réseau | Profil |
|-------|-----|-----|--------|--------|
| MOCHAbin | Armada 7040 Quad 1.8GHz | 4 GB | 2× SFP+ 10GbE + 4× GbE | SecuBox Pro |
| ESPRESSObin v7 | Armada 3720 Dual 1.2GHz | 1–2 GB | WAN + 2× LAN DSA | SecuBox Lite |
| ESPRESSObin Ultra | Armada 3720 Dual 1.2GHz | 2 GB | WAN PoE + 4× LAN + Wi-Fi | SecuBox Lite+ |
| Raspberry Pi 4 | BCM2711 Quad 1.5GHz | 2-8 GB | GbE + USB | SecuBox Lite |
| Raspberry Pi 400 | BCM2711 Quad 1.8GHz | 4 GB | GbE + USB | SecuBox Lite |
| Raspberry Pi 5 | BCM2712 Quad 2.4GHz | 4-8 GB | GbE + USB | SecuBox Full |
| VM x86_64 | Any | 2+ GB | Virtio/NAT | SecuBox Full |

---

## Packages (93 modules)

### Core & Dashboard
| Package | Description |
|---------|-------------|
| `secubox-core` | Python lib, nginx config, auth framework |
| `secubox-hub` | Central dashboard with roadmap, system health |
| `secubox-portal` | Web authentication, JWT login/logout |
| `secubox-system` | System control (services, logs, updates) |

### Security (6 modules)
| Package | Description |
|---------|-------------|
| `secubox-crowdsec` | IDS/IPS with CrowdSec, decisions, bouncers |
| `secubox-wireguard` | VPN dashboard, peers, keys, QR codes |
| `secubox-auth` | OAuth2 + captive portal vouchers |
| `secubox-nac` | Network Access Control, device guardian |
| `secubox-waf` | Web Application Firewall (300+ rules) |
| `secubox-users` | Unified identity (7 services sync) |

### Network (5 modules)
| Package | Description |
|---------|-------------|
| `secubox-netmodes` | Network modes (router, bridge, AP) |
| `secubox-dpi` | Deep Packet Inspection (netifyd) |
| `secubox-qos` | QoS / Bandwidth manager (HTB) |
| `secubox-vhost` | Virtual hosts nginx + ACME |
| `secubox-haproxy` | HAProxy dashboard, backends, ACLs |

### Monitoring (3 modules)
| Package | Description |
|---------|-------------|
| `secubox-netdata` | Real-time monitoring dashboard |
| `secubox-mediaflow` | Media streaming detection |
| `secubox-cdn` | CDN cache (Squid/nginx) |

### DNS & Email (6 modules)
| Package | Description |
|---------|-------------|
| `secubox-dns` | DNS Master / BIND zones, DNSSEC |
| `secubox-mail` | Postfix/Dovecot email server |
| `secubox-mail-lxc` | LXC container for mail |
| `secubox-webmail` | Roundcube/SOGo webmail |
| `secubox-webmail-lxc` | LXC container for webmail |

### Publishing (5 modules)
| Package | Description |
|---------|-------------|
| `secubox-droplet` | File publisher |
| `secubox-streamlit` | Streamlit app platform |
| `secubox-streamforge` | Streamlit app manager |
| `secubox-metablogizer` | Static site generator + Tor |
| `secubox-publish` | Unified publishing dashboard |

### Metapackages
| Package | Description |
|---------|-------------|
| `secubox-full` | All modules for MOCHAbin/VM |
| `secubox-lite` | Core modules for ESPRESSObin |

---

## Quick Start

### VirtualBox (Fastest)

Test SecuBox in VirtualBox in 2 minutes:

```bash
# One-liner: Download, convert, create VM, and start
curl -sLO https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz && \
gunzip secubox-live-amd64-bookworm.img.gz && \
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI && \
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/create-secubox-vm.sh | bash -s -- secubox-live.vdi
```

Or step by step:

```bash
# 1. Download and extract
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# 2. Use the VM creation script
./scripts/create-secubox-vm.sh secubox-live-amd64-bookworm.img

# 3. Access (wait 30-60s for boot)
ssh -p 2222 root@localhost       # Password: secubox
firefox https://localhost:9443   # Web UI
```

See [wiki/Live-USB-VirtualBox.md](wiki/Live-USB-VirtualBox.md) for full documentation.

### Live USB (Hardware)

Boot directly from USB with all packages pre-installed:

```bash
# Download latest release
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz

# Flash to USB (replace /dev/sdX with your device)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync

# Boot from USB and access:
# Web UI: https://<IP>:443
# SSH: root / secubox
```

See [docs/LIVE-USB.md](docs/LIVE-USB.md) for full documentation.

### Installation (from APT repo)

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/gpg.key | gpg --dearmor -o /etc/apt/keyrings/secubox.gpg
echo "deb [signed-by=/etc/apt/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" \
  > /etc/apt/sources.list.d/secubox.list

# Install
apt update
apt install secubox-full   # or secubox-lite for minimal

# Access dashboard
firefox https://localhost/
# Login: admin / secubox
```

### Build from source

```bash
git clone https://github.com/gkerma/secubox-deb
cd secubox-deb

# Build all packages
bash scripts/build-all-local.sh bookworm amd64

# Build image for VM
sudo bash image/build-image.sh --board vm-x64 --vdi

# Create VirtualBox VM
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi
```

---

## API Reference

All modules expose REST APIs via Unix sockets proxied by nginx at `/api/v1/<module>/`.

### Authentication

```bash
# Login
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secubox"}'

# Response: {"success":true,"token":"eyJ...","username":"admin","role":"admin"}

# Use token for protected endpoints
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

### Common Endpoints (all modules)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Module status |
| `/health` | GET | No | Health check |

### Hub API (`/api/v1/hub/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Full dashboard data |
| `/menu` | GET | Dynamic sidebar menu |
| `/modules` | GET | Module status list |
| `/alerts` | GET | Active alerts |
| `/roadmap` | GET | Migration progress |
| `/system_health` | GET | System health score |
| `/network_summary` | GET | Network status |

### CrowdSec API (`/api/v1/crowdsec/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | CrowdSec metrics |
| `/decisions` | GET | Active decisions |
| `/alerts` | GET | Security alerts |
| `/bouncers` | GET | Bouncer status |
| `/ban` | POST | Ban IP address |
| `/unban` | POST | Unban IP address |

### WireGuard API (`/api/v1/wireguard/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/interfaces` | GET | WG interfaces |
| `/peers` | GET | Peer list |
| `/peer` | POST | Add peer |
| `/peer/{id}` | DELETE | Remove peer |
| `/qrcode/{peer}` | GET | Peer QR code |

See [docs/API-REFERENCE.md](docs/API-REFERENCE.md) for complete API documentation.

---

## Configuration

Main configuration: `/etc/secubox/secubox.conf` (TOML)

```toml
[general]
hostname = "secubox"
domain = "local"
timezone = "Europe/Paris"

[auth]
jwt_secret = "your-secret-key"
session_timeout = 86400

[network]
wan_interface = "eth0"
lan_interface = "eth1"

[crowdsec]
api_url = "http://127.0.0.1:8080"
```

---

## Development

```bash
# Setup dev environment
bash setup-dev.sh
source .venv/bin/activate

# Run single module API
cd packages/secubox-crowdsec
uvicorn api.main:app --reload --host 127.0.0.1 --port 8001

# Build single package
dpkg-buildpackage -us -uc -b

# Deploy to VM
scp -P 2222 *.deb root@localhost:/tmp/
ssh -p 2222 root@localhost "dpkg -i /tmp/*.deb"
```

---

## Documentation

- [Live USB Guide](docs/LIVE-USB.md) — Bootable USB image, quick start
- [User Guide](docs/USER-GUIDE.md) — Installation, configuration, usage
- [API Reference](docs/API-REFERENCE.md) — Complete REST API documentation
- [Migration Map](.claude/MIGRATION-MAP.md) — Module status tracking
- [CLAUDE.md](CLAUDE.md) — Instructions for Claude Code

---

## License

Apache-2.0 © 2026 CyberMind · Gandalf / gkerma
