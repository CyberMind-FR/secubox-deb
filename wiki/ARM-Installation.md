# ARM Installation via U-Boot

[Francais](ARM-Installation-FR) | [中文](ARM-Installation-ZH)

This guide covers installing SecuBox on ARM boards (Marvell Armada) using U-Boot to flash the image to eMMC from USB or SD card.

## Supported Boards

| Board | SoC | RAM | Profile |
|-------|-----|-----|---------|
| ESPRESSObin v7 | Armada 3720 | 1-2 GB | secubox-lite |
| ESPRESSObin Ultra | Armada 3720 | 1-4 GB | secubox-lite |
| MOCHAbin | Armada 7040 | 4 GB | secubox-full |

## eMMC Storage Limits

| Board | eMMC | Max Image | Default |
|-------|------|-----------|---------|
| ESPRESSObin v7 (no eMMC) | — | SD only | — |
| ESPRESSObin v7 (4GB) | 4 GB | **3.5 GB** | Use `--size 3.5G` |
| ESPRESSObin v7 (8GB) | 8 GB | 6 GB | 4 GB |
| ESPRESSObin Ultra | 8 GB | 6 GB | 4 GB |
| MOCHAbin | 8 GB | 6 GB | 4 GB |

**Notes:**
- Leave ~500MB-2GB free for data partition and wear leveling
- For 4GB eMMC boards: build with `--size 3.5G`
- MOCHAbin can use SATA/NVMe for larger installations
- `gzwrite` requires RAM to decompress (~350MB buffer)

## Prerequisites

- Serial console adapter (USB-TTL)
- USB drive or SD card with the image
- Serial terminal: `screen`, `minicom`, or PuTTY

### Serial Console Settings

```
Baud rate:    115200
Data bits:    8
Parity:       None
Stop bits:    1
Flow control: None
```

```bash
# Linux
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
```

## Prepare Boot Media

### Option A: USB Drive (Recommended)

Format a USB drive with a FAT32 or ext4 partition and copy the image:

```bash
# Download the image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Mount USB drive (assuming /dev/sdb1)
sudo mount /dev/sdb1 /mnt

# Copy image
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/

# Unmount
sudo umount /mnt
```

### Option B: SecuBox Live USB

If using a SecuBox Live USB, copy the image to the persistence partition (partition 4):

```bash
# The persistence partition is already ext4
sudo mount /dev/sdX4 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

## U-Boot Flash Procedure

### 1. Enter U-Boot

Connect serial console and power on the board. Press any key to stop autoboot:

```
Hit any key to stop autoboot:  0
=>
```

### 2. Initialize USB

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found
```

### 3. Verify Storage

```
=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB
```

### 4. List Files

For FAT32 partition (partition 1):
```
=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

For ext4 partition (partition 4 on Live USB):
```
=> ls usb 0:4
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

### 5. Flash to eMMC

```bash
# Set load address (needs ~350MB free RAM)
=> setenv loadaddr 0x1000000

# Load image from USB
# For FAT32 (partition 1):
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# For ext4 (partition 4):
=> load usb 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# Write to eMMC with automatic decompression
=> gzwrite mmc 1 $loadaddr $filesize
```

The `gzwrite` command decompresses and writes directly to eMMC. This takes 2-5 minutes depending on image size.

### 6. Configure Boot Order

```bash
# Set eMMC as primary boot device
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

# Reboot
=> reset
```

## Alternative: Flash from SD Card

If the image is on SD card instead of USB:

```bash
=> mmc dev 0                    # Select SD card
=> ls mmc 0:1                   # List files
=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize    # Write to eMMC
```

## Boot Device Reference

| Device | U-Boot | Description |
|--------|--------|-------------|
| SD Card | `mmc 0` | microSD slot |
| eMMC | `mmc 1` | Internal eMMC (install target) |
| USB | `usb 0` | USB storage |
| SATA | `scsi 0` | SATA drive (MOCHAbin) |

## Board-Specific Notes

### ESPRESSObin v7

- **eMMC**: Optional, may need to boot from SD if not present
- **RAM**: 1GB models have limited space, use `loadaddr 0x1000000`
- **Network**: eth0=WAN, lan0/lan1=LAN (DSA switch)

### ESPRESSObin Ultra

- **eMMC**: 8GB built-in
- **RAM**: Up to 4GB
- **Network**: Same as v7

### MOCHAbin

- **eMMC**: 8GB built-in
- **RAM**: 4GB (can hold larger images)
- **Network**: Multiple 10GbE + GbE ports
- **SATA**: Can also install to SATA drive

```bash
# MOCHAbin: Flash to SATA instead of eMMC
=> scsi scan
=> gzwrite scsi 0 $loadaddr $filesize
```

## Troubleshooting

### USB Not Detected

```bash
=> usb reset
=> usb tree        # Show USB device tree
=> usb info        # Detailed USB info
```

### eMMC Not Detected

```bash
=> mmc list        # List MMC devices
=> mmc dev 1       # Select eMMC
=> mmc info        # Show eMMC info
```

### Load Fails (File Not Found)

```bash
=> ls usb 0        # List all partitions
=> ls usb 0:1      # Try partition 1
=> ls usb 0:2      # Try partition 2
```

### Out of Memory

For 1GB boards, ensure no other data is loaded:

```bash
=> setenv loadaddr 0x1000000    # Use lower address
```

### Reset Environment

```bash
=> env default -a
=> saveenv
```

### Check Current Environment

```bash
=> print                    # Show all variables
=> print boot_targets       # Show boot order
=> print loadaddr           # Show load address
```

## Post-Installation

After flashing, the board boots SecuBox automatically.

### Default Credentials

| User | Password |
|------|----------|
| root | secubox |
| secubox | secubox |

### First Steps

1. Connect via SSH: `ssh root@<IP>`
2. Change passwords: `passwd`
3. Access Web UI: `https://<IP>:8443`

### Network Interfaces

| Board | WAN | LAN |
|-------|-----|-----|
| ESPRESSObin | eth0 | lan0, lan1 |
| MOCHAbin | eth0 | eth1-eth4, sfp0-sfp1 |

## See Also

- [[Installation]] - General installation guide
- [[Live-USB]] - Try without installing
- [[Modules]] - Available modules
