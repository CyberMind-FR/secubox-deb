# Live USB Guide

[Francais](Live-USB-FR) | [中文](Live-USB-ZH)

Boot SecuBox directly from a USB drive with all packages pre-installed.

## Download

**Latest Release:** [secubox-live-amd64-bookworm.img.gz](https://github.com/CyberMind-FR/secubox-deb/releases/latest)

## Features

| Feature | Description |
|---------|-------------|
| UEFI Boot | Modern GRUB bootloader |
| SquashFS | Compressed root (~250MB) |
| Persistence | Save changes across reboots |
| Slipstream | All 30+ SecuBox packages included |

## Flash to USB

### Linux / macOS

```bash
# Find your USB device
lsblk

# Flash (replace /dev/sdX with your device!)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### Windows

1. Download [Rufus](https://rufus.ie/) or [balenaEtcher](https://etcher.balena.io/)
2. Extract the `.img.gz` file to get `.img`
3. Select the `.img` file
4. Select your USB drive
5. Click Write/Flash

## Boot Menu Options

| Option | Description |
|--------|-------------|
| **SecuBox Live** | Normal boot with persistence |
| **Safe Mode** | Minimal drivers for troubleshooting |
| **No Persistence** | Fresh start, changes not saved |
| **To RAM** | Load entire system to memory |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web UI | admin | admin |
| SSH | root | secubox |
| SSH | secubox | secubox |

**Important:** Change passwords after first boot!

## Network Access

After booting:

1. Find IP: `ip addr` or check router DHCP leases
2. Web UI: `https://<IP>:8443`
3. SSH: `ssh root@<IP>`

Default network configuration:
- DHCP client on all interfaces
- Fallback: 192.168.1.1/24

## Persistence

Changes saved automatically:
- `/home/*` - User files
- `/etc/*` - Configuration
- `/var/log/*` - Logs
- Installed packages

### Reset Persistence

```bash
# Boot with "No Persistence", then:
sudo mkfs.ext4 -L persistence /dev/sdX3
```

## Partition Layout

| Partition | Size | Type | Purpose |
|-----------|------|------|---------|
| p1 | 512MB | EFI | GRUB bootloader |
| p2 | 2GB | FAT32 | Live system (SquashFS) |
| p3 | Remaining | ext4 | Persistence |

## Verification

```bash
# Download checksums
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/SHA256SUMS

# Verify
sha256sum -c SHA256SUMS --ignore-missing
```

## Troubleshooting

### USB Not Booting

1. Enter BIOS/UEFI (F2, F12, Del, Esc)
2. Enable USB boot
3. Disable Secure Boot
4. Set USB as first boot device

### Black Screen

1. Try "Safe Mode" from boot menu
2. Add `nomodeset` to kernel parameters:
   - Press `e` at GRUB
   - Add `nomodeset` to `linux` line
   - Press Ctrl+X

### No Network

```bash
ip link show
sudo systemctl restart networking
sudo dhclient eth0
```

## Building from Source

```bash
git clone https://github.com/CyberMind-FR/secubox-deb
cd secubox-deb
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

## See Also

- [[Installation]] - Permanent installation
- [[Configuration]] - System setup
- [[Troubleshooting]] - More solutions
