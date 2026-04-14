# SecuBox

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [FR](Home-FR) | [中文](Home-ZH)

Complete security appliance solution ported from OpenWrt to Debian bookworm. Designed for GlobalScale ARM64 boards (MOCHAbin, ESPRESSObin) and x86_64 systems. **125 packages** with **2000+ API endpoints**.

---

## 🔴 BOOT — Quick Start

### VirtualBox (2 Minutes) ⭐

Test SecuBox instantly in VirtualBox — no USB drive needed:

```bash
# Download latest image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# Convert to VDI format
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# Create and start VM
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh
chmod +x create-vbox-vm.sh
./create-vbox-vm.sh secubox-live.vdi
```

**One-liner with auto-download:**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

See [[Live-USB-VirtualBox]] for full documentation.

### Live USB (Hardware) ⚡

Boot directly from USB on physical hardware:

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

See [[Live-USB]] for complete guide.

### APT Installation (Existing Debian)

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # or secubox-lite
```

See [[Installation]] for detailed instructions.

---

## 🟠 AUTH — Access Credentials

| Service | Username | Password |
|---------|----------|----------|
| **Web UI** | admin | secubox |
| **SSH** | root | secubox |
| **Access** | https://localhost:9443 | SSH port 2222 |

---

## 🟢 ROOT — System Requirements

| Board | SoC | Profile | Use Case |
|-------|-----|---------|----------|
| MOCHAbin | Armada 7040 | Full | Enterprise Gateway |
| ESPRESSObin v7 | Armada 3720 | Lite | Home/SMB Router |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Home with Wi-Fi |
| Raspberry Pi 400 | BCM2711 | Full | Maker Projects |
| VM x86_64 | Any | Full | Testing/Development |
| QEMU ARM64 | Emulated | Full | ARM testing on x86 |

---

## 🟣 MIND — Feature Overview

| Stack | Description | Modules |
|-------|-------------|---------|
| 🟠 **AUTH** | Authentication, ZeroTrust, MFA | auth, portal, users, nac |
| 🟡 **WALL** | Firewall, CrowdSec, WAF, IDS/IPS | crowdsec, waf, threats, ipblock |
| 🔴 **BOOT** | Deployment, provisioning | cloner, vault, vm, rezapp |
| 🟣 **MIND** | AI, behavioral analysis, DPI | dpi, netifyd, ai-insights, soc |
| 🟢 **ROOT** | System, CLI, hardening | core, hub, system, console |
| 🔵 **MESH** | Network, WireGuard, QoS | wireguard, haproxy, netmodes, turn |

**Total: 125 packages**

See [[MODULES-EN|Modules]] for complete module documentation.

---

## 🔵 MESH — Documentation

### Getting Started
- [[Live-USB-VirtualBox|VirtualBox Quick Start]] ⭐
- [[Live-USB]] — Bootable USB guide
- [[ARM-Installation]] — ARM boards & U-Boot ⚡
- [[QEMU-ARM64]] — ARM emulation on x86 🖥️

### Configuration
- [[Configuration]] — System configuration
- [[Troubleshooting]] — Common issues

### Reference
- [[MODULES-EN|Modules]] — All 125 modules
- [[API-Reference]] — REST API (2000+ endpoints)

---

## 🟡 WALL — Security Features

- **CrowdSec** — Community-driven IDS/IPS
- **WAF** — 300+ ModSecurity rules
- **nftables** — Default DROP policy
- **AI-Insights** — ML threat detection
- **IPBlock** — Automated blocklist management
- **MAC-Guard** — MAC address control

---

## Links

- [GitHub Repository](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
