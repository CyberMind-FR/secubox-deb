# Live USB to VirtualBox — Quick Start Guide

Test SecuBox on VirtualBox in minutes using the pre-built live image.

## Prerequisites

- VirtualBox 7.0+ installed
- 8GB free disk space
- 4GB RAM available

## Quick Start (One-Liner)

```bash
# Download and create VM in one command
curl -sL https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz | \
  gunzip > secubox-live.img && \
  VBoxManage convertfromraw secubox-live.img secubox-live.vdi --format VDI && \
  bash <(curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh) secubox-live.vdi
```

## Step-by-Step Guide

### 1. Download the Live Image

```bash
# From GitHub Releases
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# Extract
gunzip secubox-live-amd64-bookworm.img.gz
```

### 2. Convert IMG to VDI

VirtualBox requires VDI format:

```bash
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI
```

### 3. Create the VM

#### Option A: Using the Script

```bash
# Download and run the VM creation script
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh
chmod +x create-secubox-vm.sh
./create-secubox-vm.sh secubox-live.vdi
```

#### Option B: Manual Commands

```bash
VM_NAME="SecuBox-Live"
VDI_PATH="$(pwd)/secubox-live.vdi"

# Create VM
VBoxManage createvm --name "$VM_NAME" --ostype "Debian_64" --register

# Configure VM
VBoxManage modifyvm "$VM_NAME" \
    --memory 4096 \
    --cpus 2 \
    --vram 128 \
    --graphicscontroller vboxsvga \
    --firmware efi \
    --boot1 disk \
    --nic1 nat \
    --natpf1 "SSH,tcp,,2222,,22" \
    --natpf1 "HTTPS,tcp,,9443,,443"

# Add storage
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$VDI_PATH"
```

### 4. Start the VM

```bash
# GUI mode
VBoxManage startvm "SecuBox-Live" --type gui

# Headless mode (background)
VBoxManage startvm "SecuBox-Live" --type headless
```

### 5. Access SecuBox

Wait 30-60 seconds for boot, then:

| Access | Command/URL |
|--------|-------------|
| **SSH** | `ssh -p 2222 root@localhost` |
| **Web UI** | https://localhost:9443 |
| **Password** | `secubox` |

## Complete Script

Save as `secubox-vbox-quickstart.sh`:

```bash
#!/bin/bash
# SecuBox VirtualBox Quick Start
# Usage: ./secubox-vbox-quickstart.sh [image.img]

set -euo pipefail

IMG="${1:-secubox-live-amd64-bookworm.img}"
VDI="${IMG%.img}.vdi"
VM_NAME="SecuBox-Live-$(date +%Y%m%d)"

# Check if image exists
if [[ ! -f "$IMG" ]]; then
    echo "Downloading SecuBox Live image..."
    wget -q --show-progress \
        https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
    gunzip secubox-live-amd64-bookworm.img.gz
    IMG="secubox-live-amd64-bookworm.img"
    VDI="${IMG%.img}.vdi"
fi

# Convert to VDI if needed
if [[ ! -f "$VDI" ]]; then
    echo "Converting to VDI format..."
    VBoxManage convertfromraw "$IMG" "$VDI" --format VDI
fi

# Remove existing VM
VBoxManage unregistervm "$VM_NAME" --delete 2>/dev/null || true

# Create VM
echo "Creating VM: $VM_NAME"
VBoxManage createvm --name "$VM_NAME" --ostype "Debian_64" --register

# Configure
VBoxManage modifyvm "$VM_NAME" \
    --memory 4096 \
    --cpus 2 \
    --vram 128 \
    --graphicscontroller vboxsvga \
    --firmware efi \
    --boot1 disk \
    --nic1 nat \
    --natpf1 "SSH,tcp,,2222,,22" \
    --natpf1 "HTTPS,tcp,,9443,,443" \
    --clipboard bidirectional

# Storage
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 \
    --type hdd --medium "$(realpath "$VDI")"

# Start
echo "Starting VM..."
VBoxManage startvm "$VM_NAME" --type gui

echo ""
echo "=== SecuBox VM Ready ==="
echo "SSH:   ssh -p 2222 root@localhost"
echo "Web:   https://localhost:9443"
echo "Pass:  secubox"
echo ""
echo "Wait 30-60 seconds for boot to complete."
```

## Troubleshooting

### API errors / "Invalid credentials" (v2.1.1 Fix)

If you see API 502 errors or "Invalid credentials" after login, upgrade Python packages:

```bash
ssh -p 2222 root@localhost
pip3 install --break-system-packages 'pydantic>=2.0' 'fastapi>=0.100' 'uvicorn>=0.25'
systemctl restart secubox-hub secubox-auth secubox-system
```

This issue is fixed in v2.1.1+ images.

### VM won't boot (black screen)

```bash
# Try BIOS instead of EFI
VBoxManage modifyvm "SecuBox-Live" --firmware bios
```

### Port already in use

```bash
# Use different ports
VBoxManage modifyvm "SecuBox-Live" --natpf1 delete "SSH"
VBoxManage modifyvm "SecuBox-Live" --natpf1 delete "HTTPS"
VBoxManage modifyvm "SecuBox-Live" --natpf1 "SSH,tcp,,2223,,22"
VBoxManage modifyvm "SecuBox-Live" --natpf1 "HTTPS,tcp,,9444,,443"
```

### Graphics issues

```bash
# Disable 3D acceleration
VBoxManage modifyvm "SecuBox-Live" --accelerate3d off --graphicscontroller vmsvga
```

### Check VM status

```bash
VBoxManage list runningvms
VBoxManage showvminfo "SecuBox-Live" | head -40
```

## Cleanup

```bash
# Stop VM
VBoxManage controlvm "SecuBox-Live" poweroff

# Delete VM and files
VBoxManage unregistervm "SecuBox-Live" --delete

# Remove VDI
rm -f secubox-live.vdi
```

## See Also

- [Installation Guide](Installation.md)
- [Build from Source](Building.md)
- [Hardware Deployment](Hardware.md)
