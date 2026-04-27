# Multi-Boot Live OS

**SecuBox v2.2.3** — Dual-architecture bootable live system with RAM-based execution.

---

## Overview

Multi-architecture bootable live operating system supporting both ARM64 (U-Boot) and AMD64 (UEFI) systems from a single image. Designed for:

- **Live Demo/Recovery** — Boot from USB for demonstrations, repair, or factory reset
- **Pi Zero Eye Remote** — USB mass storage gadget presenting bootable image to MOCHAbin/ESPRESSObin
- **Portable Installation** — Boot on any ARM64 or AMD64 system with persistent data

### Supported Architectures

| Architecture | Boot Method | Target Boards |
|--------------|-------------|---------------|
| **ARM64** | U-Boot | ESPRESSObin, MOCHAbin, Armada boards |
| **AMD64** | UEFI GRUB | Any x86_64 PC, laptop, server |
| **Shared** | — | Cross-architecture persistent storage |

---

## Use Cases

### 1. Eye Remote USB Boot (Pi Zero W)

The Pi Zero runs Eye Remote firmware and presents the multiboot image as USB mass storage. ESPRESSObin/MOCHAbin boots directly from the USB storage.

```
┌─────────────┐     USB OTG      ┌─────────────────┐
│  Pi Zero W  │◄────────────────►│  ESPRESSObin    │
│ Eye Remote  │  mass_storage    │    U-Boot       │
│ (32GB uSD)  │  16GB multiboot  │  boots from USB │
└─────────────┘                  └─────────────────┘
```

**Setup:**
1. Flash Eye Remote image to SD card (32GB recommended)
2. Copy multiboot image to `/var/lib/secubox/eye-remote/storage.img`
3. Connect Pi Zero to ESPRESSObin via USB OTG
4. ESPRESSObin U-Boot detects USB storage and boots SecuBox

### 2. Direct USB Boot

Flash multiboot image to USB stick, boot any ARM64/AMD64 system directly.

```bash
# Flash to USB drive
xzcat secubox-multiboot-2.2.3.img.xz | sudo dd of=/dev/sdX bs=4M status=progress
```

### 3. Demo/Recovery Mode

Pre-configured SecuBox environment for:
- Live demonstrations to customers
- System recovery and repair
- Factory reset and cloning
- Installation to eMMC/NVMe

---

## Partition Layout

| Part | Type | Size | Mount | Purpose |
|------|------|------|-------|---------|
| 1 | EFI (FAT32) | 512MB | /boot/efi | UEFI + U-Boot boot files |
| 2 | ext4 | 3GB | / (ARM64) | SecuBox ARM64 live rootfs |
| 3 | ext4 | 3GB | / (AMD64) | SecuBox AMD64 live rootfs |
| 4 | ext4 | 8GB+ | /srv/data | Shared application data |

### Boot Files (Partition 1)

```
/boot/efi/
├── EFI/
│   └── BOOT/
│       ├── BOOTX64.EFI      # GRUB for AMD64
│       └── grub.cfg         # GRUB config
├── Image                    # ARM64 kernel
├── initrd.img               # ARM64 initramfs
├── dtbs/                    # ARM64 device trees
├── boot.scr                 # U-Boot script (ARM64)
├── grub/
│   └── grub.cfg             # GRUB config (AMD64)
├── vmlinuz                  # AMD64 kernel
├── initrd-amd64.img         # AMD64 initramfs
└── flash/
    └── secubox-emmc.img.gz  # eMMC flasher image
```

---

## Boot Flow

### ARM64 (ESPRESSObin/MOCHAbin)

1. U-Boot loads `boot.scr` from partition 1
2. Kernel + initrd from partition 1
3. Rootfs from partition 2
4. Mounts partition 4 as /srv/data
5. Bind-mounts shared paths

### AMD64 (UEFI)

1. UEFI loads GRUB from EFI/BOOT/BOOTX64.EFI
2. GRUB loads vmlinuz + initrd from partition 1
3. Rootfs from partition 3
4. Mounts partition 4 as /srv/data
5. Bind-mounts shared paths

---

## Shared Data Structure

```
/srv/data/
├── etc/
│   └── secubox/             # Shared configs
│       ├── api.toml
│       ├── users.json
│       ├── tls/
│       └── modules/
├── var/
│   └── lib/
│       └── secubox/         # Application state
│           ├── crowdsec/
│           ├── haproxy/
│           ├── wireguard/
│           └── dpi/
├── srv/
│   └── secubox/             # Service data
│       ├── mitmproxy/
│       ├── nginx/
│       └── certs/
└── log/
    └── secubox/             # Shared logs
```

---

## Building

### Build Multiboot Image

```bash
# Build complete multi-boot image (16GB default)
sudo ./image/multiboot/build-multiboot.sh --size 16G --output secubox-multiboot.img

# With desktop environment
sudo ./image/multiboot/build-multiboot.sh --size 32G --desktop --output secubox-multiboot-desktop.img
```

### GitHub Actions CI

Automated builds via `.github/workflows/build-multiboot.yml`:
- Configurable image sizes (8/16/32GB)
- Optional desktop environment
- Automatic release publishing on tags

---

## Eye Remote Integration

### Preparing SD Card for Pi Zero

```bash
# 1. Flash Eye Remote base image
sudo dd if=output/secubox-eye-remote-*.img of=/dev/sdX bs=4M status=progress

# 2. Expand root partition to fill card
sudo parted /dev/sdX resizepart 2 100%
sudo resize2fs /dev/sdXp2

# 3. Copy multiboot image as storage
sudo mount /dev/sdXp2 /mnt
sudo cp output/secubox-multiboot.img /mnt/var/lib/secubox/eye-remote/storage.img
sudo umount /mnt
```

### Gadget Configuration

The USB mass_storage gadget presents `/var/lib/secubox/eye-remote/storage.img` to the connected host. ESPRESSObin U-Boot detects it as a USB drive and boots from it.

---

## Flash to eMMC

From either architecture:

```bash
secubox-flash-emmc  # Interactive installer

# Or manual:
gunzip -c /boot/efi/flash/secubox-emmc.img.gz | dd of=/dev/mmcblk0 bs=4M status=progress
```

---

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web UI | admin | secubox |
| SSH | root | secubox |
| User | secubox | secubox |

---

## Troubleshooting

### Not Booting from Eye Remote

1. Check storage.img exists: `ls -lh /var/lib/secubox/eye-remote/storage.img`
2. Verify gadget status: `systemctl status secubox-eye-gadget`
3. Check USB connection: `dmesg | grep usb`

### ESPRESSObin U-Boot Commands

```
usb start
usb dev 0
ls usb 0:1
load usb 0:1 $loadaddr boot.scr
source $loadaddr
```

### AMD64 Not Booting

1. Verify UEFI boot mode (not Legacy/CSM)
2. Check Secure Boot is disabled
3. Select USB drive in boot menu (F12/F2/ESC)

---

## Downloads

- [Latest Release](https://github.com/CyberMind-FR/secubox-deb/releases/latest)
- [v2.2.3 Multiboot](https://github.com/CyberMind-FR/secubox-deb/releases/tag/multiboot-v2.2.3)

---

## Version History

| Version | Changes |
|---------|---------|
| **v2.2.3** | GitHub Actions CI, Eye Remote integration, wiki docs |
| **v2.2.2** | Initial multiboot system with ARM64 + AMD64 support |

---

*See also: [[Eye-Remote]] | [[ARM-Installation]] | [[Live-USB]]*
