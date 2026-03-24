# Installation Guide

[Francais](Installation-FR) | [中文](Installation-ZH)

## Quick Install (APT)

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install full suite
sudo apt install secubox-full

# Or minimal installation
sudo apt install secubox-lite
```

## Manual APT Setup

```bash
# Import GPG key
curl -fsSL https://apt.secubox.in/gpg.key | gpg --dearmor -o /etc/apt/keyrings/secubox.gpg

# Add repository
echo "deb [signed-by=/etc/apt/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" \
  | sudo tee /etc/apt/sources.list.d/secubox.list

# Update and install
sudo apt update
sudo apt install secubox-full
```

## System Image Installation

### Download Images

| Board | Image |
|-------|-------|
| MOCHAbin | `secubox-mochabin-bookworm.img.gz` |
| ESPRESSObin v7 | `secubox-espressobin-v7-bookworm.img.gz` |
| ESPRESSObin Ultra | `secubox-espressobin-ultra-bookworm.img.gz` |
| VM x64 | `secubox-vm-x64-bookworm.img.gz` |

### Flash to SD Card / eMMC

```bash
# Download
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-mochabin-bookworm.img.gz

# Flash to SD card
gunzip -c secubox-mochabin-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### VirtualBox Setup

```bash
# Decompress
gunzip secubox-vm-x64-bookworm.img.gz

# Convert to VDI
VBoxManage convertfromraw secubox-vm-x64-bookworm.img secubox.vdi --format VDI

# Create VM
VBoxManage createvm --name SecuBox --ostype Debian_64 --register
VBoxManage modifyvm SecuBox --memory 2048 --cpus 2 --nic1 nat --firmware efi
VBoxManage storagectl SecuBox --name SATA --add sata
VBoxManage storageattach SecuBox --storagectl SATA --port 0 --device 0 --type hdd --medium secubox.vdi

# Start
VBoxManage startvm SecuBox
```

### QEMU Setup

```bash
gunzip secubox-vm-x64-bookworm.img.gz
qemu-system-x86_64 \
  -drive file=secubox-vm-x64-bookworm.img,format=raw \
  -enable-kvm \
  -m 2048 \
  -smp 2 \
  -bios /usr/share/ovmf/OVMF.fd
```

## Package Selection

### Metapackages

| Package | Description |
|---------|-------------|
| `secubox-full` | All modules (recommended for MOCHAbin/VM) |
| `secubox-lite` | Core modules (for ESPRESSObin) |

### Individual Packages

**Core:**
- `secubox-core` - Shared libraries, auth framework
- `secubox-hub` - Central dashboard
- `secubox-portal` - Web authentication

**Security:**
- `secubox-crowdsec` - IDS/IPS with CrowdSec
- `secubox-waf` - Web Application Firewall
- `secubox-auth` - OAuth2, captive portal
- `secubox-nac` - Network Access Control

**Networking:**
- `secubox-wireguard` - VPN dashboard
- `secubox-haproxy` - Load balancer
- `secubox-dpi` - Deep Packet Inspection
- `secubox-qos` - Bandwidth management
- `secubox-netmodes` - Network modes

**Applications:**
- `secubox-mail` - Email server
- `secubox-dns` - DNS server
- `secubox-netdata` - Monitoring

## Post-Installation

### First Boot

1. Access Web UI: `https://<IP>:8443`
2. Login: admin / admin
3. Change password immediately
4. Configure network settings
5. Enable required modules

### Security Hardening

```bash
# Change default passwords
passwd root
passwd secubox

# Update system
apt update && apt upgrade

# Enable firewall
systemctl enable --now nftables
```

## Requirements

### Hardware

| Spec | Minimum | Recommended |
|------|---------|-------------|
| RAM | 1 GB | 2+ GB |
| Storage | 4 GB | 16+ GB |
| CPU | ARM64/x86_64 | 2+ cores |

### Software

- Debian 12 (bookworm)
- systemd
- Python 3.11+

## See Also

- [[Live-USB]] - Try without installing
- [[Configuration]] - System setup
- [[Modules]] - Module details
