<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Build System

SecuBox-DEB provides multiple build scripts for creating bootable images targeting different platforms.

---

## Quick Start

```bash
# Live USB for x64 (kiosk + autologin enabled by default)
sudo bash image/build-live-usb.sh

# ARM64 board (MOCHAbin)
sudo bash image/build-image.sh --board mochabin

# VirtualBox VM
sudo bash image/build-image.sh --board vm-x64 --vdi
```

---

## Build Scripts

| Script | Target | Output |
|--------|--------|--------|
| `build-live-usb.sh` | x64 Live USB | `.img` / `.img.gz` |
| `build-image.sh` | ARM64 boards / x64 VM | `.img` / `.vdi` |
| `build-rpi-usb.sh` | Raspberry Pi 400 | `.img` |
| `build-installer-iso.sh` | x64 ISO installer | `.iso` |
| `create-vbox-vm.sh` | VirtualBox VM | VM config |

---

## Live USB (x64)

The primary build target for testing and deployment on x64 hardware.

### Command

```bash
sudo bash image/build-live-usb.sh [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--suite SUITE` | Debian suite | `bookworm` |
| `--size SIZE` | Image size | `8G` |
| `--local-cache` | Use local APT cache | Off |
| `--no-kiosk` | Disable GUI kiosk | Kiosk ON |
| `--no-persistence` | No persistent partition | Persistence ON |
| `--no-compress` | Skip gzip (faster build) | Compress ON |
| `--preseed FILE` | Include preseed config | None |
| `--overlay` | Advanced overlay layout | Off |

### Features

- **UEFI + Legacy BIOS** hybrid boot
- **Root autologin** on console (TTY1-6)
- **GUI kiosk mode** on TTY7 (Chromium fullscreen)
- **Network auto-detection** at first boot
- **Persistence partition** for config/data survival
- **All SecuBox packages** pre-installed (~125 modules)

### Output

```
output/secubox-live-amd64-bookworm.img      # Raw image
output/secubox-live-amd64-bookworm.img.gz   # Compressed
```

### Flash to USB

```bash
# Compressed image
zcat output/secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress

# Raw image
sudo dd if=output/secubox-live-amd64-bookworm.img of=/dev/sdX bs=4M status=progress
```

---

## ARM64 Boards

Build images for Marvell Armada-based hardware.

### Command

```bash
sudo bash image/build-image.sh --board <BOARD> [OPTIONS]
```

### Supported Boards

| Board | SoC | Profile | Use Case |
|-------|-----|---------|----------|
| `mochabin` | Armada 7040 | SecuBox Pro | Production gateway |
| `espressobin-v7` | Armada 3720 | SecuBox Lite | Small office |
| `espressobin-ultra` | Armada 3720 | SecuBox Lite+ | Extended storage |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--board BOARD` | Target board | `mochabin` |
| `--suite SUITE` | Debian suite | `bookworm` |
| `--size SIZE` | Image size | `8G` |
| `--vdi` | Also create VDI | Off |
| `--local-cache` | Use local APT cache | Off |
| `--slipstream` | Include local .deb packages | ON |

### Examples

```bash
# MOCHAbin (default)
sudo bash image/build-image.sh --board mochabin

# ESPRESSObin v7
sudo bash image/build-image.sh --board espressobin-v7

# With local package cache
sudo bash image/build-image.sh --board mochabin --local-cache --slipstream
```

---

## VirtualBox VM

Build and run SecuBox in VirtualBox for development/testing.

### Build Image

```bash
sudo bash image/build-image.sh --board vm-x64 --vdi
```

### Create VM

```bash
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi
```

### Run VM

```bash
bash scripts/run-vbox.sh
```

### Port Forwarding (NAT)

| Service | Host Port | Guest Port |
|---------|-----------|------------|
| SSH | 2222 | 22 |
| HTTPS | 9443 | 443 |
| HTTP | 8080 | 80 |

### Connect

```bash
ssh -p 2222 root@localhost
# Password: secubox
```

---

## Local Build Cache

Speed up builds using local APT cache.

### Setup (once)

```bash
sudo bash scripts/setup-local-cache.sh
```

### Build with Cache

```bash
sudo bash image/build-live-usb.sh --local-cache
sudo bash image/build-image.sh --board mochabin --local-cache
```

---

## Slipstream Local Packages

Include locally-built `.deb` packages in the image.

### Build Packages

```bash
bash scripts/build-all-local.sh bookworm amd64
# Output: output/debs/*.deb
```

### Include in Image

```bash
sudo bash image/build-live-usb.sh --slipstream
```

The build script automatically includes all `.deb` files from `output/debs/`.

---

## First Boot

The `firstboot.sh` script runs automatically on first boot:

1. **Board detection** - Identifies hardware platform
2. **SSH keys** - Generates unique host keys
3. **JWT secrets** - Creates API authentication tokens
4. **Hostname** - Sets `secubox-<board>` hostname
5. **Network** - Applies netplan configuration
6. **nftables** - Loads firewall rules
7. **Services** - Enables SecuBox services

### Manual Trigger

```bash
sudo /usr/lib/secubox/firstboot.sh
```

---

## Kiosk Mode

GUI kiosk mode provides a fullscreen Chromium browser on TTY7.

### Enable/Disable

```bash
# Status
secubox-kiosk-setup status

# Enable
secubox-kiosk-setup enable

# Disable (console only)
secubox-kiosk-setup disable
```

### Services

| Service | Description |
|---------|-------------|
| `secubox-kiosk.service` | X11 kiosk (TTY7) |
| `secubox-console.service` | TUI dashboard |

### Boot Parameters

```
# In GRUB/kernel cmdline
secubox.kiosk=1    # Enable kiosk
secubox.kiosk=0    # Disable kiosk
```

---

## Preseed Configuration

Pre-configure a SecuBox installation with custom settings.

### Create Preseed Archive

```bash
tar -czvf preseed.tar.gz \
  etc/secubox/*.toml \
  etc/netplan/*.yaml \
  etc/wireguard/*.conf
```

### Build with Preseed

```bash
sudo bash image/build-live-usb.sh --preseed preseed.tar.gz
```

### Apply Manually

```bash
sudo /usr/lib/secubox/preseed-apply.sh /path/to/preseed.tar.gz
```

---

## Troubleshooting

### Build Fails at Debootstrap

```bash
# Clear cache and retry
sudo rm -rf /tmp/secubox-rootfs
sudo bash image/build-live-usb.sh
```

### VirtualBox NVRAM Error

```bash
# Remove corrupted NVRAM file
rm "/home/$USER/VirtualBox VMs/SecuBox-*/SecuBox-*.nvram"
VBoxManage startvm "SecuBox-VM-x64" --type gui
```

### SSH Connection Refused

1. Check VM is fully booted (login prompt visible)
2. Verify port forwarding: `VBoxManage showvminfo "SecuBox-VM-x64" | grep NAT`
3. Check SSH service: `systemctl status ssh` (inside VM)

### Kiosk Not Starting

```bash
# Check logs
journalctl -u secubox-kiosk -f

# Verify X11
ls /tmp/.X11-unix/

# Manual start
startx /usr/bin/chromium --kiosk http://localhost
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.9.0 | 2026-05 | Health banner, CDN injection |
| 1.8.0 | 2026-04 | 125 modules, SOC dashboard |
| 1.7.0 | 2026-03 | Kiosk mode, TUI console |
| 1.6.0 | 2026-02 | Live USB, persistence |

---

## See Also

- [[Home]] - Wiki home
- [[Architecture-Boot]] - Boot process details
- [[Developer-Guide]] - Development setup
- [[QEMU-ARM64]] - ARM64 emulation
