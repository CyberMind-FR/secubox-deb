# QEMU ARM64 Virtual Machine

Run SecuBox ARM64 images on x86_64 hosts using QEMU emulation.

## Overview

| Feature | Value |
|---------|-------|
| Host Arch | x86_64 (Intel/AMD) |
| Guest Arch | ARM64 (aarch64) |
| Emulation | Full system emulation |
| Performance | ~10-20x slower than native |
| Use Case | Testing, development |

> **Note:** For production ARM64 deployments, use real ARM hardware (ESPRESSObin, MOCHAbin, Raspberry Pi) or ARM64 cloud instances.

## Requirements

### Install QEMU ARM64

```bash
# Debian/Ubuntu
sudo apt install qemu-system-arm qemu-efi-aarch64

# Fedora
sudo dnf install qemu-system-aarch64 edk2-aarch64

# Arch
sudo pacman -S qemu-system-aarch64 edk2-ovmf
```

### Minimum System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Host RAM | 8GB | 16GB+ |
| Host CPU | 4 cores | 8+ cores |
| Disk | 20GB free | 50GB+ |

## Quick Start

### 1. Download ARM64 Image

```bash
# From releases
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Or build locally
sudo bash image/build-image.sh --board vm-arm64
```

### 2. Run with Script

```bash
# GUI mode (default)
bash image/create-qemu-arm64-vm.sh secubox-espressobin-v7-bookworm.img.gz

# Headless mode (serial console)
bash image/create-qemu-arm64-vm.sh --no-gui secubox-espressobin-v7-bookworm.img.gz

# Custom resources
bash image/create-qemu-arm64-vm.sh --ram 2048 --cpus 2 secubox-arm64.img
```

### 3. Access

| Service | URL/Command |
|---------|-------------|
| SSH | `ssh -p 2222 root@localhost` |
| Web UI | http://localhost:8080 |
| HTTPS | https://localhost:8443 |
| Console | Serial in terminal |

Default credentials: `admin` / `secubox`

## Manual QEMU Command

```bash
# Decompress image
gunzip -k secubox-espressobin-v7-bookworm.img.gz

# Create UEFI vars file
truncate -s 64M /tmp/uefi-vars.fd

# Run QEMU
qemu-system-aarch64 \
  -name secubox-arm64 \
  -machine virt,gic-version=3 \
  -cpu cortex-a72 \
  -smp 4 \
  -m 4096 \
  -drive if=pflash,format=raw,file=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd,readonly=on \
  -drive if=pflash,format=raw,file=/tmp/uefi-vars.fd \
  -drive if=virtio,format=raw,file=secubox-espressobin-v7-bookworm.img \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80,hostfwd=tcp::8443-:443 \
  -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -serial mon:stdio \
  -nographic
```

## Script Options

```
Usage: create-qemu-arm64-vm.sh [OPTIONS] <image>

Options:
  --ram SIZE       RAM in MB (default: 4096)
  --cpus N         CPU cores (default: 4)
  --name NAME      VM name (default: secubox-arm64)
  --convert        Convert to qcow2 (faster I/O)
  --no-gui         Headless mode
  --ssh-port PORT  SSH forward port (default: 2222)
  --http-port PORT HTTP forward port (default: 8080)
```

## Performance Tips

### 1. Use qcow2 Format

```bash
# Convert for better I/O performance
qemu-img convert -f raw -O qcow2 secubox.img secubox.qcow2

# Or use --convert flag
bash create-qemu-arm64-vm.sh --convert secubox.img
```

### 2. Enable KVM (ARM64 hosts only)

If running on native ARM64 hardware:

```bash
# Check KVM availability
ls /dev/kvm

# Add -enable-kvm to QEMU command
qemu-system-aarch64 -enable-kvm ...
```

### 3. Allocate More Resources

```bash
# More RAM and CPUs = faster (within reason)
bash create-qemu-arm64-vm.sh --ram 8192 --cpus 8 secubox.img
```

## Networking

### Port Forwarding (Default)

The script uses QEMU user-mode networking with port forwarding:

| Host Port | Guest Port | Service |
|-----------|------------|---------|
| 2222 | 22 | SSH |
| 8080 | 80 | HTTP |
| 8443 | 443 | HTTPS |

### Bridge Networking (Advanced)

For full network access, use bridge networking:

```bash
# Create bridge (requires root)
sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip addr add 192.168.100.1/24 dev br0

# Run QEMU with tap device
sudo qemu-system-aarch64 \
  ... \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0
```

## Troubleshooting

### Boot Hangs at UEFI

**Cause:** Missing or incompatible UEFI firmware.

**Solution:**
```bash
# Install UEFI firmware
sudo apt install qemu-efi-aarch64

# Verify file exists
ls -la /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
```

### Very Slow Performance

**Cause:** ARM64 emulation on x86 is inherently slow.

**Solutions:**
1. Use fewer services (disable unused SecuBox modules)
2. Allocate more RAM and CPUs
3. Use real ARM hardware for production testing

### Network Not Working

**Cause:** Port forwarding conflicts.

**Solution:**
```bash
# Check if ports are in use
ss -tlnp | grep -E '2222|8080|8443'

# Use different ports
bash create-qemu-arm64-vm.sh --ssh-port 2223 --http-port 8081 secubox.img
```

### Can't Access Web UI

1. Wait for full boot (ARM emulation is slow, ~2-5 minutes)
2. Check services are running:
   ```bash
   ssh -p 2222 root@localhost
   systemctl status nginx secubox-hub
   ```

## Comparison: Emulation vs Native

| Aspect | QEMU ARM64 | Native ARM (ESPRESSObin) |
|--------|------------|--------------------------|
| Speed | ~10-20x slower | Native |
| Setup | Easy | Requires hardware |
| Cost | Free | ~$50-150 |
| Use Case | Dev/Testing | Production |
| Network | Emulated | Real hardware |

## See Also

- [ARM Installation Guide](ARM-Installation)
- [ESPRESSObin Guide](ESPRESSObin)
- [VirtualBox x64 Setup](Installation#virtualbox)
- [Live USB Guide](Live-USB)
