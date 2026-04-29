# SecuBox VirtualBox Setup Guide

Quick guide to run SecuBox in VirtualBox for testing and development.

---

## Requirements

- **VirtualBox 7.0+** with Extension Pack
- **2GB+ RAM** available for VM
- **8GB+ disk space** for VDI
- **Host OS**: Linux, macOS, or Windows

---

## Quick Start (Automated)

```bash
# Download and run the setup script
curl -fsSL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/vbox-setup.sh | bash
```

Or download manually:
```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-vm-x64-bookworm.vdi.gz
gunzip secubox-vm-x64-bookworm.vdi.gz
bash scripts/vbox-setup.sh --vdi secubox-vm-x64-bookworm.vdi
```

---

## Manual Setup

### 1. Download the VDI Image

From GitHub Releases:
```bash
# Latest release
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-vm-x64-bookworm.vdi.gz

# Decompress
gunzip secubox-vm-x64-bookworm.vdi.gz
```

### 2. Create VirtualBox VM

```bash
# Create VM
VBoxManage createvm --name "SecuBox" --ostype Debian_64 --register

# Configure VM
VBoxManage modifyvm "SecuBox" \
  --memory 2048 \
  --cpus 2 \
  --firmware efi \
  --graphicscontroller vmsvga \
  --vram 64 \
  --nic1 bridged \
  --bridgeadapter1 "eth0" \
  --audio-driver pulse \
  --boot1 disk \
  --boot2 none \
  --boot3 none \
  --boot4 none

# Add SATA controller
VBoxManage storagectl "SecuBox" --name "SATA" --add sata --bootable on

# Attach VDI
VBoxManage storageattach "SecuBox" \
  --storagectl "SATA" \
  --port 0 \
  --device 0 \
  --type hdd \
  --medium secubox-vm-x64-bookworm.vdi

# Start VM
VBoxManage startvm "SecuBox" --type gui
```

### 3. First Boot

The VM boots directly into **Kiosk Mode** (Chromium fullscreen on SecuBox WebUI).

**Default credentials:**
- Username: `root`
- Password: `secubox`

**Console access:** Press `Ctrl+Alt+F2` for root shell

---

## Boot Modes

SecuBox offers three boot modes selectable from GRUB menu:

| Mode | Description | Use Case |
|------|-------------|----------|
| **Kiosk Mode** | Fullscreen browser on WebUI | Production, demo |
| **Console Mode** | Standard shell login | Administration |
| **Recovery Mode** | Single-user mode | Troubleshooting |

To access GRUB menu: Hold `Shift` during boot or press `Escape` at BIOS.

---

## Network Configuration

### Bridged Mode (Recommended)
VM gets IP from your network's DHCP:
```bash
VBoxManage modifyvm "SecuBox" --nic1 bridged --bridgeadapter1 "eth0"
```

### NAT with Port Forwarding
Access WebUI via localhost:
```bash
VBoxManage modifyvm "SecuBox" --nic1 nat
VBoxManage modifyvm "SecuBox" --natpf1 "https,tcp,,9443,,9443"
VBoxManage modifyvm "SecuBox" --natpf1 "ssh,tcp,,2222,,22"
```
- WebUI: https://localhost:9443
- SSH: `ssh -p 2222 root@localhost`

### Host-Only
Isolated network for testing:
```bash
VBoxManage hostonlyif create
VBoxManage modifyvm "SecuBox" --nic1 hostonly --hostonlyadapter1 "vboxnet0"
```

---

## Troubleshooting

### VM tries PXE boot instead of disk

**Solution:** Disable network boot
```bash
VBoxManage modifyvm "SecuBox" --nic1 none
# Boot once, then re-enable:
VBoxManage modifyvm "SecuBox" --nic1 bridged --bridgeadapter1 "eth0"
```

Or in GUI: Settings → System → uncheck "Network" in Boot Order

### Black screen after GRUB

**Solution:** Use VMSVGA graphics
```bash
VBoxManage modifyvm "SecuBox" --graphicscontroller vmsvga --vram 64
```

### Kiosk doesn't start

**Solution:** Check kiosk service
```bash
# Press Ctrl+Alt+F2 for console
systemctl status secubox-kiosk
journalctl -u secubox-kiosk -f
```

### Guest Additions

For better integration (shared folders, clipboard):
```bash
# In VM console
apt update && apt install -y build-essential linux-headers-$(uname -r)
mount /dev/sr0 /mnt
/mnt/VBoxLinuxAdditions.run
reboot
```

---

## VM Export/Import

### Export as OVA
```bash
VBoxManage export "SecuBox" -o secubox.ova
```

### Import OVA
```bash
VBoxManage import secubox.ova
```

---

## See Also

- [Installation Guide](Installation-Guide.md)
- [Kiosk Mode Configuration](Kiosk-Mode.md)
- [Network Modes](Network-Modes.md)
- [API Reference](API-Reference.md)
