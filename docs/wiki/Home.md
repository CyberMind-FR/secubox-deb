# SecuBox-Deb

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [FR](Home-FR) | [中文](Home-ZH)

Complete security appliance ported from OpenWrt to Debian bookworm. Designed for GlobalScale ARM64 boards (MOCHAbin, ESPRESSObin) and x86_64 systems.

**125 packages · 2000+ API endpoints · ANSSI CSPN candidate**

---

## 🔴 BOOT — Quick Start

### VirtualBox (Recommended) ⭐

```bash
# One-liner with auto-download
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

See [[Live-USB-VirtualBox]] for details.

### Live USB

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

See [[Live-USB]] for complete guide.

### APT Install

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

---

## 🟠 AUTH — Access

| Service | Username | Password | Port |
|---------|----------|----------|------|
| Web UI | admin | secubox | 9443 |
| SSH | root | secubox | 2222 |

---

## 🟢 ROOT — Hardware

| Board | SoC | Profile |
|-------|-----|---------|
| MOCHAbin | Armada 7040 | Full |
| ESPRESSObin v7 | Armada 3720 | Lite |
| VM x86_64 | Any | Full |

---

## 🟣 MIND — Module Stack

| Stack | Function | Key Modules |
|-------|----------|-------------|
| 🟠 AUTH | Authentication | auth, portal, nac |
| 🟡 WALL | Firewall/IDS | crowdsec, waf, ipblock |
| 🔴 BOOT | Deployment | cloner, vault, vm |
| 🟣 MIND | AI/DPI | dpi, netifyd, ai-insights |
| 🟢 ROOT | System | core, hub, system |
| 🔵 MESH | Network | wireguard, haproxy, qos |

See [[Modules]] for all 125 modules.

---

## 🔵 MESH — Documentation

### Getting Started
- [[Live-USB-VirtualBox|VirtualBox]] ⭐
- [[Live-USB|USB Boot]]
- [[ARM-Installation|ARM Boards]]
- [[QEMU-ARM64|QEMU Emulation]]

### Configuration
- [[Configuration]]
- [[Troubleshooting]]

### Architecture
- [[Architecture-Boot|Boot Layers]]
- [[Architecture-Modules|Module Design]]
- [[Architecture-Security|Security Model]]

### Development
- [[Developer-Guide]]
- [[Design-System|UI/UX]]
- [[API-Reference]]

---

## 👁️ Eye Remote

Compact USB gadget display for SecuBox monitoring.

**Hardware:** Pi Zero W + HyperPixel 2.1 Round (480×480)
**Connection:** USB OTG (10.55.0.0/30) or WiFi

| Page | Description |
|------|-------------|
| [[Eye-Remote]] | Overview & quick links |
| [[Eye-Remote-Hardware]] | Hardware setup |
| [[Eye-Remote-Implementation]] | Software architecture |
| [[Eye-Remote-Bootstrap]] | Boot device mode |
| [[eye-remote-icons]] | Icon reference |

```bash
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz
```

---

## 🟡 WALL — Security

- **CrowdSec** — Community IDS/IPS
- **WAF** — 300+ ModSecurity rules
- **nftables** — Default DROP
- **AI-Insights** — ML threat detection

---

## Links

- [GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [CyberMind](https://cybermind.fr)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
