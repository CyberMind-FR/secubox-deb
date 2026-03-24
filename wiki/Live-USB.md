# SecuBox Live USB

Boot SecuBox directly from a USB drive - no installation required.

## Features

| Feature | Description |
|---------|-------------|
| UEFI Boot | Modern GRUB bootloader |
| SquashFS | Compressed root (~250MB) |
| Persistence | Save changes across reboots |
| Slipstream | All SecuBox packages included |

## Download

**Latest Release:** [secubox-live-amd64-bookworm.img.gz](https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz)

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

Use [Rufus](https://rufus.ie/) or [balenaEtcher](https://etcher.balena.io/):

1. Download and extract the `.img.gz` file
2. Select the `.img` file in Rufus/Etcher
3. Select your USB drive
4. Click Write/Flash

## Boot Menu

| Option | Use Case |
|--------|----------|
| **SecuBox Live** | Normal boot with persistence |
| **Safe Mode** | Hardware compatibility issues |
| **No Persistence** | Fresh start, no saved changes |
| **To RAM** | Run entirely from memory |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web UI | admin | admin |
| SSH | root | secubox |
| SSH | secubox | secubox |

> **Security:** Change passwords immediately after first boot!

## Network Access

After booting:

1. Find IP address: `ip addr` or check your router's DHCP leases
2. Web UI: `https://<IP>:8443`
3. SSH: `ssh root@<IP>`

### Default Network

- DHCP client on all interfaces
- Fallback: 192.168.1.1/24 on first interface

## Persistence

Changes are automatically saved to the persistence partition:

- `/home/*` - User files
- `/etc/*` - Configuration
- `/var/log/*` - Logs
- Installed packages

### Reset Persistence

```bash
# Boot with "No Persistence" option, then:
sudo mkfs.ext4 -L persistence /dev/sdX3
```

## Verification

```bash
# Download checksum
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/SHA256SUMS

# Verify
sha256sum -c SHA256SUMS --ignore-missing
```

## Troubleshooting

### USB Not Booting

1. Enter BIOS/UEFI setup (F2, F12, Del, or Esc at boot)
2. Enable USB boot
3. Disable Secure Boot
4. Set USB as first boot device

### Black Screen

1. Try "Safe Mode" from boot menu
2. Add `nomodeset` to kernel parameters:
   - Press `e` at GRUB menu
   - Add `nomodeset` to the `linux` line
   - Press Ctrl+X to boot

### No Network

```bash
# Check interfaces
ip link show

# Restart networking
sudo systemctl restart networking

# Manual DHCP
sudo dhclient eth0
```

## Building from Source

```bash
git clone https://github.com/CyberMind-FR/secubox-deb
cd secubox-deb

# Build live USB image
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

See [[Building Images]] for more options.

## See Also

- [[Installation]] - Permanent installation
- [[First Boot]] - Initial configuration
- [[Troubleshooting]] - More solutions
