# SecuBox-DEB VM Testing Guide

Test SecuBox images in QEMU or VirtualBox before deploying to hardware.

## Available Images

| Image | Size | Format | Use Case |
|-------|------|--------|----------|
| `secubox-vm-x64-bookworm.img` | 4GB | RAW | QEMU direct boot |
| `secubox-vm-x64-bookworm.vdi` | ~1.3GB | VDI | VirtualBox |
| `secubox-live-amd64-bookworm.img` | 8GB | RAW | USB Live boot |

## QEMU Testing

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install qemu-system-x86 ovmf

# Check KVM support
lsmod | grep kvm
```

### With KVM (Hardware Acceleration)

```bash
qemu-system-x86_64 \
  -m 4096 \
  -enable-kvm \
  -cpu host \
  -smp 4 \
  -drive file=output/secubox-vm-x64-bookworm.img,format=raw,if=virtio \
  -bios /usr/share/ovmf/OVMF.fd \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -vga virtio \
  -display gtk \
  -name "SecuBox-DEB"
```

### Without KVM (Software Emulation)

For nested virtualization or systems without KVM:

```bash
qemu-system-x86_64 \
  -m 2048 \
  -cpu qemu64 \
  -smp 2 \
  -drive file=output/secubox-vm-x64-bookworm.img,format=raw,if=virtio \
  -bios /usr/share/ovmf/OVMF.fd \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -vga std \
  -display gtk \
  -name "SecuBox-DEB (TCG)"
```

### Headless Mode (Server)

```bash
qemu-system-x86_64 \
  -m 4096 \
  -enable-kvm \
  -cpu host \
  -smp 4 \
  -drive file=output/secubox-vm-x64-bookworm.img,format=raw,if=virtio \
  -bios /usr/share/ovmf/OVMF.fd \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -nographic \
  -serial mon:stdio
```

### Access Points

Once booted:

| Service | URL/Command |
|---------|-------------|
| Web UI | https://localhost:9443 |
| SSH | `ssh -p 2222 root@localhost` |

**Default credentials:** `root` / `secubox`

## VirtualBox Testing

### Convert Image to VDI

```bash
qemu-img convert -f raw -O vdi \
  output/secubox-vm-x64-bookworm.img \
  output/secubox-vm-x64-bookworm.vdi
```

### Create VM via CLI

```bash
# Create VM
VBoxManage createvm --name "SecuBox-DEB" --ostype "Debian_64" --register

# Configure VM
VBoxManage modifyvm "SecuBox-DEB" \
  --memory 4096 \
  --cpus 4 \
  --firmware efi \
  --nic1 nat \
  --natpf1 "ssh,tcp,,2222,,22" \
  --natpf1 "https,tcp,,9443,,443"

# Attach storage
VBoxManage storagectl "SecuBox-DEB" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "SecuBox-DEB" --storagectl "SATA" --port 0 --device 0 \
  --type hdd --medium output/secubox-vm-x64-bookworm.vdi

# Start VM
VBoxManage startvm "SecuBox-DEB"
```

### Create VM via GUI

1. **New VM**: Name: `SecuBox-DEB`, Type: Linux, Version: Debian (64-bit)
2. **Memory**: 4096 MB minimum
3. **Hard disk**: Use existing - select `secubox-vm-x64-bookworm.vdi`
4. **Settings > System**: Enable EFI
5. **Settings > Network**: NAT with port forwarding:
   - SSH: Host 2222 → Guest 22
   - HTTPS: Host 9443 → Guest 443

## ARM Images (QEMU)

### ESPRESSObin v7 / Generic ARM64

```bash
qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a72 \
  -m 2048 \
  -smp 4 \
  -drive file=output/secubox-espressobin-v7-bookworm.img,format=raw,if=virtio \
  -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -nographic
```

### Raspberry Pi 400

```bash
qemu-system-aarch64 \
  -M raspi4b \
  -m 4096 \
  -drive file=output/secubox-rpi-arm64-bookworm.img,format=raw,if=sd \
  -net nic -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -nographic
```

## Verification Checklist

After boot, verify:

```bash
# Connect via SSH
ssh -p 2222 root@localhost

# Check SecuBox services
systemctl status nginx
systemctl status secubox-*

# Check web UI
curl -sk https://localhost:9443 | head -20

# Check version
cat /etc/secubox/version
```

## Troubleshooting

### KVM Not Available

```
Could not access KVM kernel module: No such file or directory
```

**Solution**: Use TCG mode (remove `-enable-kvm -cpu host`) or enable virtualization in BIOS.

### EFI Boot Fails

```
No bootable device
```

**Solution**: Ensure OVMF/UEFI firmware is installed:
```bash
sudo apt install ovmf  # x86_64
sudo apt install qemu-efi-aarch64  # ARM64
```

### Port Already in Use

```
Could not set up host forwarding rule 'tcp::9443-:443'
```

**Solution**: Use different host ports:
```bash
-net user,hostfwd=tcp::19443-:443,hostfwd=tcp::12222-:22
```

## Performance Tips

1. **Use KVM** when available (10-100x faster)
2. **virtio drivers** for disk and network
3. **Allocate sufficient RAM** (4GB recommended)
4. **Use SSD** for image storage

---

*SecuBox-DEB v1.6.0 - CyberMind*
