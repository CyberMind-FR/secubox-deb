# QEMU ARM64 Emulation

Test SecuBox OS on ARM64 without physical hardware.

---

## Quick Start

```bash
# Install QEMU
sudo apt install qemu-system-aarch64 qemu-efi-aarch64

# Download ARM64 image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-vm-arm64-bookworm.qcow2

# Run
qemu-system-aarch64 \
    -M virt -cpu cortex-a72 -m 2G -smp 2 \
    -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    -drive file=secubox-vm-arm64-bookworm.qcow2,format=qcow2 \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::9443-:443 \
    -nographic
```

---

## Access

| Service | Command |
|---------|---------|
| SSH | `ssh -p 2222 root@localhost` |
| Web UI | `https://localhost:9443` |

**Credentials:** root / secubox

---

## Build from Source

```bash
cd secubox-deb
sudo bash image/build-image.sh --board vm-arm64
```

Output: `output/secubox-vm-arm64-bookworm.qcow2`

---

## Performance Notes

- QEMU ARM64 emulation is slow on x86 hosts
- Use KVM on ARM64 hosts for native speed
- Recommend 2GB+ RAM, 2+ CPUs

---

*← Back to [[Home|SecuBox OS]]*
