# ESPRESSObin v7 — SecuBox Installation Guide

## Hardware

- **SoC**: Marvell Armada 3720 (Cortex-A53 Dual-core 1.2GHz)
- **RAM**: 1-2 GB DDR4
- **Storage**: eMMC (optional) / microSD
- **Network**: 1x WAN GbE + 2x LAN (Marvell 88E6341 DSA switch)
- **Profile**: SecuBox Lite (optimized for limited RAM)

## Storage Limits

| Model | eMMC | microSD | Recommended Image |
|-------|------|---------|-------------------|
| ESPRESSObin v7 (no eMMC) | — | Up to 128GB | SD card boot |
| ESPRESSObin v7 (4GB eMMC) | 4 GB | Up to 128GB | **3.5GB max** |
| ESPRESSObin v7 (8GB eMMC) | 8 GB | Up to 128GB | 4GB default |
| ESPRESSObin Ultra | 8 GB | Up to 128GB | 4GB default |

**Important eMMC constraints:**
- Default image size: **4GB** (fits 8GB eMMC)
- For 4GB eMMC boards, use `--size 3.5G` when building
- Leave ~500MB free for data partition and wear leveling
- U-Boot `gzwrite` requires enough RAM to decompress (~350MB)

## Pre-requisites

1. USB drive formatted with partition 4 as ext4 (persistence partition from Live USB)
2. SecuBox image: `secubox-espressobin-v7-bookworm.img.gz`
3. Serial console (115200 8N1) connected to the board

## Installation via U-Boot (USB to eMMC)

### 1. Prepare USB Drive

Copy the compressed image to the persistence partition (partition 4):

```bash
# Mount the USB persistence partition
mount /dev/sdX4 /mnt

# Copy the image
cp secubox-espressobin-v7-bookworm.img.gz /mnt/

# Unmount
umount /mnt
```

### 2. Boot into U-Boot

Connect serial console and power on the board. Press any key to stop autoboot:

```
Hit any key to stop autoboot:  0
=>
```

### 3. Detect USB Storage

```
=> usb reset
resetting USB...
Bus usb@58000: Register 2000104 NbrPorts 2
Starting the controller
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found
```

### 4. Verify USB Contents

```
=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB (60437492 x 512)

=> ls usb 0:4
<DIR>       4096 .
<DIR>       4096 ..
<DIR>      16384 lost+found
               8 persistence.conf
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

### 5. Flash to eMMC

```bash
# Set load address (must have enough space for ~300MB compressed image)
=> setenv loadaddr 0x1000000

# Load compressed image from USB partition 4
=> load usb 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz
314543223 bytes read in 3422 ms (87.7 MiB/s)

# Write directly to eMMC (mmc 1) with decompression
=> gzwrite mmc 1 $loadaddr $filesize
```

The `gzwrite` command decompresses and writes the image directly to eMMC. This takes several minutes.

### 6. Boot SecuBox

```
=> boot
```

Or set eMMC as default boot:

```
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
=> reset
```

## Alternative: Flash from SD Card

If using SD card instead of USB:

```bash
=> mmc dev 0           # Select SD card (mmc 0)
=> ls mmc 0:4          # List files on partition 4
=> load mmc 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize   # Write to eMMC (mmc 1)
```

## Boot Targets

| Device | U-Boot Name | Description |
|--------|-------------|-------------|
| SD Card | mmc 0 | microSD slot |
| eMMC | mmc 1 | Internal eMMC (target) |
| USB | usb 0 | USB storage |

## Network Interfaces

After boot, SecuBox configures:

| Interface | Role | Description |
|-----------|------|-------------|
| eth0 | WAN | External network (DHCP client) |
| lan0 | LAN | Switch port 1 |
| lan1 | LAN | Switch port 2 |
| br-lan | Bridge | LAN bridge (lan0 + lan1) |

## Default Credentials

- **Root password**: `secubox`
- **SSH**: Enabled on LAN interfaces
- **Web UI**: `https://<lan-ip>/`

## Troubleshooting

### USB not detected

```
=> usb reset
=> usb tree
```

### eMMC not detected

```
=> mmc list
=> mmc dev 1
=> mmc info
```

### Check environment

```
=> print
=> print boot_targets
```

### Reset to defaults

```
=> env default -a
=> saveenv
```

## Serial Console Settings

- **Baud rate**: 115200
- **Data bits**: 8
- **Parity**: None
- **Stop bits**: 1
- **Flow control**: None

Linux command:
```bash
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
```
