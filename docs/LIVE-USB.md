# SecuBox Live USB

Bootable live USB image for SecuBox security appliance.

## Features

- **UEFI Boot** with GRUB bootloader
- **SquashFS** compressed root filesystem (~250MB)
- **OverlayFS** for runtime changes
- **Persistence partition** for saving changes across reboots
- **Slipstream** all SecuBox packages pre-installed

## Download

Get the latest release from [GitHub Releases](https://github.com/CyberMind-FR/secubox-deb/releases) or build from source.

## Flash to USB

```bash
# Decompress and write to USB drive (replace /dev/sdX with your device)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

**Warning:** This will erase all data on the target device. Double-check the device name!

### Find your USB device

```bash
# List block devices
lsblk

# Or use dmesg after inserting USB
dmesg | tail -20
```

## Boot Options

The GRUB menu offers several boot modes:

| Option | Description |
|--------|-------------|
| **SecuBox Live** | Normal boot with persistence enabled |
| **Safe Mode** | Minimal drivers for troubleshooting |
| **No Persistence** | Fresh start, changes not saved |
| **To RAM** | Load entire system to memory (remove USB after boot) |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| SSH | root | secubox |
| SSH | secubox | secubox |
| Web UI | admin | admin |

**Important:** Change these passwords immediately after first boot!

```bash
# Change root password
passwd

# Change secubox user password
passwd secubox
```

## Network Configuration

The live system auto-configures networking:

- **DHCP** on all detected interfaces
- **Static fallback:** 192.168.1.1/24 on first interface
- **Web UI:** https://&lt;IP&gt;:8443

### Find your IP address

```bash
ip addr show
# or
hostname -I
```

## Persistence

Changes are saved to the persistence partition automatically. This includes:

- User files in `/home`
- Configuration in `/etc`
- Installed packages
- Log files

### Disable persistence temporarily

Select "No Persistence" from the boot menu, or add `nopersistence` to kernel parameters.

### Reset persistence

```bash
# Mount persistence partition
sudo mount /dev/sdX3 /mnt

# Clear all saved changes
sudo rm -rf /mnt/*

# Unmount
sudo umount /mnt
```

## Partition Layout

| Partition | Size | Type | Mount | Description |
|-----------|------|------|-------|-------------|
| p1 | 512MB | EFI System | /boot/efi | GRUB bootloader |
| p2 | 2GB | FAT32 | /run/live/medium | Live system (squashfs) |
| p3 | Remaining | ext4 | /run/live/persistence | Persistent storage |

## Building from Source

### Prerequisites

```bash
sudo apt-get install -y \
  debootstrap parted dosfstools e2fsprogs \
  squashfs-tools grub-efi-amd64-bin grub-pc-bin \
  xorriso mtools rsync
```

### Build

```bash
# Basic build (8GB image)
sudo bash image/build-live-usb.sh --size 8G

# Without persistence partition
sudo bash image/build-live-usb.sh --size 4G --no-persistence

# With slipstream (include .deb packages)
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

### Output

```
output/
  secubox-live-amd64-bookworm.img.gz      # Compressed image
  secubox-live-amd64-bookworm.img.gz.sha256  # Checksum
```

## Verify Download

```bash
# Check SHA256 checksum
sha256sum -c secubox-live-amd64-bookworm.img.gz.sha256

# Verify GPG signature (if available)
gpg --verify SHA256SUMS.gpg
```

## Troubleshooting

### USB not booting

1. Check BIOS/UEFI settings - enable USB boot
2. Disable Secure Boot (or enroll SecuBox keys)
3. Try different USB port (USB 2.0 ports may be more compatible)

### Black screen after boot

1. Select "Safe Mode" from boot menu
2. Try adding `nomodeset` to kernel parameters

### No network

```bash
# Check interface status
ip link show

# Restart networking
sudo systemctl restart networking

# Manual DHCP
sudo dhclient eth0
```

### Persistence not working

1. Check partition exists: `lsblk`
2. Check label: `sudo blkid | grep persistence`
3. Check mount: `mount | grep persistence`

## Included Packages

The live image includes all SecuBox packages:

- **Core:** secubox-core, secubox-hub, secubox-portal
- **Security:** secubox-crowdsec, secubox-waf, secubox-auth, secubox-nac
- **Networking:** secubox-wireguard, secubox-netmodes, secubox-dpi, secubox-qos
- **Applications:** secubox-mail, secubox-gitea, secubox-nextcloud
- **Publishing:** secubox-droplet, secubox-streamlit, secubox-metablogizer

## Support

- GitHub Issues: https://github.com/CyberMind-FR/secubox-deb/issues
- Documentation: https://secubox.in/docs
