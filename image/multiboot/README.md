# SecuBox Multi-Boot Storage System

## Overview

Multi-architecture bootable storage for Pi Zero Eye Remote that supports:
- **ARM64**: ESPRESSObin/MOCHAbin via U-Boot
- **AMD64**: Any x86_64 UEFI system
- **Shared Data**: Cross-architecture application data

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

```bash
# Build complete multi-boot image
./build-multiboot.sh --size 16G --output secubox-multiboot.img

# Build AMD64 rootfs only
./build-amd64-rootfs.sh --output rootfs-amd64/

# Build ARM64 rootfs only
./build-arm64-rootfs.sh --output rootfs-arm64/
```
