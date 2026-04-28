# SecuBox Live USB — QEMU

Launch SecuBox in QEMU for testing and development.

## Quick Start

```bash
# Clone repository
git clone https://github.com/CyberMind-FR/secubox-deb.git
cd secubox-deb

# Download or build image
# Option A: Download release
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz
mv secubox-live-amd64-bookworm.img output/

# Option B: Build locally
sudo bash image/build-live-usb.sh

# Launch QEMU
bash scripts/run-qemu.sh
```

## Script Options

```bash
scripts/run-qemu.sh [OPTIONS] [IMAGE]

Options:
    -m, --memory MB     RAM size (default: 4096)
    -c, --cpus N        Number of CPUs (default: 4)
    -s, --ssh PORT      Host SSH port (default: 2222)
    -w, --https PORT    Host HTTPS port (default: 9443)
    -d, --display TYPE  Display: gtk, sdl, none, vnc
    --no-efi            Use BIOS instead of EFI
```

## Port Forwarding

| Service | Host | Guest |
|---------|------|-------|
| SSH | localhost:2222 | :22 |
| HTTPS | localhost:9443 | :443 |
| HTTP | localhost:8080 | :80 |

## Access SecuBox

### Web Dashboard

Open in browser:
```
https://localhost:9443
```

Accept the self-signed certificate warning.

### SSH Access

```bash
ssh -p 2222 root@localhost
# Password: secubox
```

### Serial Console

In QEMU window, the console is available via the display.

## Requirements

- **QEMU**: `apt install qemu-system-x86`
- **KVM** (recommended): `apt install qemu-kvm`
- **OVMF** (EFI boot): `apt install ovmf`

## Manual QEMU Command

If you prefer manual control:

```bash
qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -cpu host \
    -smp 4 \
    -drive file=output/secubox-live-amd64-bookworm.img,format=raw \
    -bios /usr/share/ovmf/OVMF.fd \
    -vga virtio \
    -display gtk \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::9443-:443 \
    -device virtio-net-pci,netdev=net0
```

## Troubleshooting

### Black Screen / Kiosk Not Loading

The kiosk expects the SecuBox network interface. If you see a black screen:

```bash
# SSH into VM
ssh -p 2222 root@localhost

# Restart kiosk (if needed)
systemctl restart secubox-kiosk
```

### No KVM Acceleration

If KVM is not available:

```bash
# Check KVM support
ls /dev/kvm

# Enable if needed (may require BIOS settings)
sudo modprobe kvm_intel  # or kvm_amd
```

Without KVM, use `--no-kvm` but expect much slower performance.

### Port Already in Use

Change ports with script options:

```bash
scripts/run-qemu.sh -s 2223 -w 9444
```

## See Also

- [[Live-USB-VirtualBox|VirtualBox Setup]]
- [[Installation|Full Installation]]
- [[Troubleshooting]]
