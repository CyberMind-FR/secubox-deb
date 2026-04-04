# SecuBox-DEB

**Security Appliance for Debian** | [Français](Home-FR) | [中文](Home-ZH) | **v1.5.0**

SecuBox is a complete security appliance solution ported from OpenWrt to Debian bookworm, designed for GlobalScale ARM64 boards (MOCHAbin, ESPRESSObin) and x86_64 systems. Now featuring **93 packages** with **2000+ API endpoints**.

---

## Quick Start

### VirtualBox (2 Minutes) ⭐

Test SecuBox instantly in VirtualBox - no USB drive needed:

```bash
# Download image
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# Convert to VDI format
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# Create and start VM (use our script)
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/create-secubox-vm.sh
chmod +x create-secubox-vm.sh
./create-secubox-vm.sh secubox-live.vdi
```

**Or one-liner with auto-download:**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/create-secubox-vm.sh | bash -s -- --download
```

**Access (wait 30-60s for boot):**

| Service | Access |
|---------|--------|
| **SSH** | `ssh -p 2222 root@localhost` |
| **Web UI** | https://localhost:9443 |
| **Password** | `secubox` |

See [[Live-USB-VirtualBox]] for full documentation and troubleshooting.

---

### Live USB (Hardware)

Boot directly from USB on physical hardware:

```bash
# Download
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz

# Flash to USB drive (replace /dev/sdX)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

See [[Live-USB]] for complete guide.

---

### APT Installation (Existing Debian)

```bash
# Add repository and install
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # or secubox-lite
```

See [[Installation]] for detailed instructions.

---

## VM Creation Script Options

The `create-secubox-vm.sh` script supports:

```bash
./create-secubox-vm.sh [OPTIONS] <image.vdi|image.img>

Options:
    --download        Download latest image automatically
    --name NAME       VM name (default: SecuBox-Live)
    --memory MB       RAM in MB (default: 4096)
    --cpus N          CPU count (default: 2)
    --ssh-port PORT   SSH port (default: 2222)
    --https-port PORT HTTPS port (default: 9443)
    --headless        Start without GUI
    --no-start        Create VM without starting
```

**Examples:**

```bash
# Download and create headless VM
./create-secubox-vm.sh --download --headless

# Custom configuration
./create-secubox-vm.sh secubox.vdi --name "SecuBox-Dev" --memory 8192 --cpus 4

# Different ports (if defaults are in use)
./create-secubox-vm.sh secubox.vdi --ssh-port 2223 --https-port 9444
```

---

## Features

| Category | Modules | Count |
|----------|---------|-------|
| **Security** | CrowdSec, WAF, NAC, Auth, Hardening, AI-Insights, IPBlock | 15 |
| **Networking** | WireGuard, HAProxy, DPI, QoS, Network Modes, Interceptor | 12 |
| **SOC** | Fleet Monitoring, Alert Correlation, Threat Maps, Console TUI | 6 |
| **Monitoring** | Netdata, Metrics, Threats, OpenClaw OSINT | 8 |
| **Applications** | Ollama, Jellyfin, HomeAssistant, Matrix, Jitsi, PeerTube | 21 |
| **System Tools** | Glances, MQTT, TURN, Vault, Cloner, VM | 22 |
| **Email & DNS** | Postfix/Dovecot, Webmail, DNS Provider | 9 |

**Total: 93 packages**

---

## Supported Hardware

| Board | SoC | Profile | Use Case |
|-------|-----|---------|----------|
| MOCHAbin | Armada 7040 | Full | Enterprise Gateway |
| ESPRESSObin v7 | Armada 3720 | Lite | Home/SMB Router |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Home with Wi-Fi |
| Raspberry Pi 4/5 | BCM2711/2712 | Lite/Full | Maker Projects |
| VM x86_64 | Any | Full | Testing/Development |

---

## Documentation

- [[Live-USB-VirtualBox]] - **VirtualBox quick start** ⭐
- [[Live-USB]] - Bootable USB guide
- [[Installation]] - Full installation
- [[Modules]] - All 93 modules
- [[API-Reference]] - REST API (2000+ endpoints)
- [[Troubleshooting]] - Common issues

---

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web UI | admin | secubox |
| SSH | root | secubox |

---

## Links

- [GitHub Repository](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)
