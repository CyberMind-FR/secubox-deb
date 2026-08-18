<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Multi-Boot Live OS

## Overview

Multi-architecture bootable live operating system with RAM-based execution and shared persistent data. Designed for:

- **Live Demo/Recovery** — Boot from USB for demonstrations, repair, or factory reset
- **Pi Zero Eye Remote** — USB mass storage gadget presenting bootable image to MOCHAbin/ESPRESSObin
- **Portable Installation** — Boot on any ARM64 or AMD64 system with persistent data

### Supported Architectures
- **ARM64**: ESPRESSObin, MOCHAbin, Armada boards via U-Boot
- **AMD64**: Any x86_64 UEFI system (PC, laptop, server)
- **Shared Data**: Cross-architecture persistent storage

## Use Cases

### 1. Eye Remote USB Boot (Pi Zero W)
The Pi Zero runs Eye Remote firmware and presents this image as USB mass storage.
ESPRESSObin/MOCHAbin boots directly from the USB storage.

```
┌─────────────┐     USB OTG      ┌─────────────────┐
│  Pi Zero W  │◄────────────────►│  ESPRESSObin    │
│ Eye Remote  │  mass_storage    │    U-Boot       │
│ (32GB uSD)  │  16GB multiboot  │  boots from USB │
└─────────────┘                  └─────────────────┘
```

### 2. Direct USB Boot
Flash to USB stick, boot any ARM64/AMD64 system directly.

### 3. Demo/Recovery Mode
Pre-configured SecuBox environment for:
- Live demonstrations
- System recovery and repair
- Factory reset and cloning
- Installation to eMMC/NVMe

## Partition Layout (16GB+ recommended)

| Part | Type | Size | Mount | Purpose |
|------|------|------|-------|---------|
| 1 | EFI (FAT32) | 512MB | /boot/efi | UEFI + U-Boot boot files |
| 2 | ext4 | 3GB | / (ARM64) | SecuBox ARM64 live rootfs |
| 3 | ext4 | 3GB | / (AMD64) | SecuBox AMD64 live rootfs |
| 4 | ext4 | 8GB+ | /srv/data | Shared application data |

## Boot Files (Partition 1)

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

## Shared Data Structure (Partition 4)

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

## Boot Flow

### ARM64 (ESPRESSObin)
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

### eMMC Flash
From either architecture:
```bash
secubox-flash-emmc  # Interactive
# or
gunzip -c /boot/efi/flash/secubox-emmc.img.gz | dd of=/dev/mmcblk0 bs=4M status=progress
```

## Build

### Build Multiboot Image
```bash
# Build complete multi-boot image (16GB default)
sudo ./build-multiboot.sh --size 16G --output secubox-multiboot.img

# With desktop environment
sudo ./build-multiboot.sh --size 32G --desktop --output secubox-multiboot-desktop.img
```

### Build Individual Components
```bash
# AMD64 rootfs only
sudo ./build-amd64-rootfs.sh --output rootfs-amd64/

# ARM64 rootfs only (uses existing ESPRESSObin tooling)
# See board/espressobin-v7/
```

### GitHub Actions
The `build-multiboot.yml` workflow automates CI builds with:
- Configurable image sizes (8/16/32GB)
- Optional desktop environment
- Automatic release publishing

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

## Version History

- **v2.2.3** — GitHub Actions CI, Eye Remote integration docs
- **v2.2.2** — Initial multiboot system with ARM64 + AMD64 support
