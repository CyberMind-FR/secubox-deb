# SecuBox-DEB Build System

Build SecuBox images for various hardware targets using the modular build system.

## Quick Start

```bash
# Build x64 VM image with SecuBox packages
sudo bash image/build-image.sh --board vm-x64 --slipstream

# Build x64 Live USB with kiosk
sudo bash image/build-live-usb.sh

# Build Raspberry Pi 400 image
sudo bash image/build-rpi-usb.sh --slipstream

# Build ESPRESSObin v7 image
sudo bash image/build-image.sh --board espressobin-v7 --slipstream
```

## Build Targets

| Target | Script | Architecture | Features |
|--------|--------|--------------|----------|
| x64 VM | `build-image.sh --board vm-x64` | amd64 | Minimal, server-oriented |
| x64 Live USB | `build-live-usb.sh` | amd64 | Full, kiosk, live boot |
| RPi 400 | `build-rpi-usb.sh` | arm64 | Full, kiosk, USB boot |
| ESPRESSObin v7 | `build-image.sh --board espressobin-v7` | arm64 | Headless, network-focused |

## Build Options

### build-image.sh

```bash
sudo bash image/build-image.sh [OPTIONS]

Options:
  --board BOARD     Target board: vm-x64, mochabin, espressobin-v7, espressobin-ultra
  --suite SUITE     Debian suite (default: bookworm)
  --out DIR         Output directory (default: ./output)
  --size SIZE       Image size (default: 4G)
  --vdi             Also generate VirtualBox VDI image
  --local-cache     Use local APT cache
  --slipstream      Include SecuBox .deb packages
  --keep-rootfs     Keep unpacked rootfs after build
```

### build-live-usb.sh

```bash
sudo bash image/build-live-usb.sh [OPTIONS]

Options:
  --suite SUITE     Debian suite (default: bookworm)
  --out DIR         Output directory (default: ./output)
  --size SIZE       Image size (default: 8G)
  --local-cache     Use local APT cache
  --no-kiosk        Disable kiosk mode
```

### build-rpi-usb.sh

```bash
sudo bash image/build-rpi-usb.sh [OPTIONS]

Options:
  --suite SUITE     Debian suite (default: bookworm)
  --size SIZE       Image size (default: 8G)
  --slipstream      Include SecuBox .deb packages
```

## Prerequisites

```bash
# Install build dependencies
sudo apt install debootstrap qemu-user-static binfmt-support \
    parted dosfstools e2fsprogs qemu-utils

# For ARM64 cross-compilation
sudo apt install qemu-system-arm

# Enable binfmt for ARM64 emulation
sudo systemctl enable --now binfmt-support
```

## Package Management

### Building Packages

```bash
# Build all SecuBox packages
bash scripts/build-packages.sh

# Packages output to: output/debs/
```

### Slipstream Installation

The `--slipstream` option includes SecuBox packages directly in the image:

1. Packages from `output/packages/` are copied to the rootfs
2. Python dependencies are installed via pip
3. Packages are installed with `dpkg -i --force-depends`
4. Broken dependencies are resolved with `apt-get -f install`

## Output Files

After a successful build:

```
output/
├── secubox-vm-x64-bookworm.img       # Raw disk image
├── secubox-vm-x64-bookworm.img.gz    # Compressed image
├── secubox-vm-x64-bookworm.img.sha256
├── secubox-vm-x64-bookworm.vdi       # VirtualBox format (if --vdi)
└── packages/                          # SecuBox .deb packages
```

## Build Process

1. **Image Creation** - Allocate sparse disk image
2. **Partitioning** - GPT/MBR with EFI and rootfs partitions
3. **Debootstrap** - Install minimal Debian base system
4. **Configuration** - APT sources, locales, network
5. **Package Installation** - apt, pip, slipstream SecuBox
6. **Kiosk Setup** (optional) - X11, Chromium, nodm
7. **Bootloader** - GRUB EFI or RPi firmware
8. **Compression** - gzip and checksum

## Modular Architecture

```
image/
├── lib/
│   └── common.sh           # Shared functions
├── profiles/
│   ├── x64-vm.conf         # VM profile
│   ├── x64-live.conf       # Live USB profile
│   ├── rpi400.conf         # Raspberry Pi profile
│   └── espressobin-v7.conf # ESPRESSObin profile
├── splash/
│   ├── boot.png            # Plymouth splash
│   ├── tui-splash.sh       # Terminal splash
│   └── kiosk-loading.sh    # Kiosk loading animation
└── plymouth/
    └── secubox/            # Plymouth theme
```

## Troubleshooting

### Loop Device Errors

```bash
# Create additional loop devices if needed
sudo mknod -m 660 /dev/loop3 b 7 3
sudo mknod -m 660 /dev/loop4 b 7 4
```

### Debootstrap Hangs

For ARM64 builds under QEMU emulation, initramfs generation is slow.
Allow 10-15 minutes for kernel configuration.

### Package Dependency Issues

Ensure Python packages use `| python3-pip` alternatives in control files:
```
Depends: python3-uvicorn | python3-pip
```

---

*SecuBox-DEB v1.6.0 - CyberMind*
