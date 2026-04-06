# ESPRESSObin — SecuBox Installation Guide

[Français](ESPRESSObin-FR) | [中文](ESPRESSObin-ZH)

Complete guide for installing SecuBox on GlobalScale ESPRESSObin boards via U-Boot.

## Hardware Variants

| Model | SoC | CPU | RAM | eMMC | Release |
|-------|-----|-----|-----|------|---------|
| ESPRESSObin v5 | Armada 3720 | 2× A53 @ 800MHz | 512MB-1GB | — | 2017 |
| ESPRESSObin v7 | Armada 3720 | 2× A53 @ 1.2GHz | 1-2GB | 0/4/8GB | 2019 |
| ESPRESSObin Ultra | Armada 3720 | 2× A53 @ 1.2GHz | 1-4GB | 8GB | 2020 |

**SecuBox Support:**
- ✅ ESPRESSObin v7 (recommended)
- ✅ ESPRESSObin Ultra
- ⚠️ ESPRESSObin v5 (limited — 512MB/1GB RAM, no SECUBOX_LITE profile)

## eMMC Storage Limits

| Configuration | eMMC | Max Image Size | Build Flag |
|---------------|------|----------------|------------|
| No eMMC | — | SD only | — |
| 4GB eMMC | 4 GB | **3.5 GB** | `--size 3.5G` |
| 8GB eMMC | 8 GB | 6 GB | default 4G OK |

**Important:**
- Default SecuBox image: **3.5GB** (fits all eMMC variants)
- `gzwrite` needs ~350MB RAM for decompression buffer
- Leave 500MB+ free for wear leveling on eMMC

## Board Layout & Connectors

```
┌─────────────────────────────────────────────────────────┐
│  ESPRESSObin v7 / Ultra                                 │
│                                                         │
│  ┌─────┐  ┌─────┐  ┌─────┐     ┌──────────┐            │
│  │ WAN │  │LAN 1│  │LAN 2│     │ USB 3.0  │            │
│  │ RJ45│  │ RJ45│  │ RJ45│     │  (blue)  │            │
│  └─────┘  └─────┘  └─────┘     └──────────┘            │
│    eth0     lan0     lan1         USB                  │
│                                                         │
│  [PWR]  [RST]                  ┌──────────┐  ┌──────┐  │
│                                │  µSD     │  │ USB  │  │
│  ○○○○○○ ← UART (J1)            │  slot    │  │ 2.0  │  │
│  123456                        └──────────┘  └──────┘  │
│                                    mmc0       USB      │
│  [DIP SW] ← Boot mode                                  │
│  1 2 3 4 5                                             │
│                                                         │
│           ┌─────────────────┐                          │
│           │     eMMC        │ ← mmc1 (under board)     │
│           │     (8GB)       │                          │
│           └─────────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

## Serial Console (UART)

### Pinout — J1 Header (6-pin)

```
Pin 1: GND    ← Connect to USB-TTL GND
Pin 2: NC
Pin 3: NC
Pin 4: RX     ← Connect to USB-TTL TX
Pin 5: TX     ← Connect to USB-TTL RX
Pin 6: NC
```

**Settings:** 115200 baud, 8N1, no flow control

```bash
# Linux
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200

# macOS
screen /dev/tty.usbserial-* 115200

# Windows: PuTTY → Serial → COM3 → 115200
```

## DIP Switch Boot Modes

The 5-position DIP switch controls boot source and CPU speed.

### Boot Source (SW1-SW3)

| SW1 | SW2 | SW3 | Boot Source |
|-----|-----|-----|-------------|
| OFF | OFF | OFF | SPI NOR Flash (default U-Boot) |
| ON  | OFF | OFF | eMMC |
| OFF | ON  | OFF | SD Card |
| ON  | ON  | OFF | UART (recovery) |
| OFF | OFF | ON  | SATA (if present) |

### CPU Speed (SW4)

| SW4 | CPU Frequency |
|-----|---------------|
| OFF | 1.2 GHz (default) |
| ON  | 800 MHz (reduced power) |

### Debug Mode (SW5)

| SW5 | Mode |
|-----|------|
| OFF | Normal |
| ON  | Debug / JTAG enable |

**For normal SecuBox operation:** All switches OFF (boot from SPI NOR which loads U-Boot → then boot from eMMC/SD)

## U-Boot Flash Procedure

### Method 1: USB Drive with gzwrite (Recommended)

#### Prepare USB Drive

```bash
# On your PC
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Format USB as FAT32 or ext4
sudo mkfs.vfat /dev/sdb1
# or
sudo mkfs.ext4 /dev/sdb1

# Copy image
sudo mount /dev/sdb1 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

#### Flash via U-Boot

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found

=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB

=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
314543223 bytes read in 3422 ms (87.7 MiB/s)

=> gzwrite mmc 1 $loadaddr $filesize
Uncompressed size: 3758096384 bytes (3.5 GiB)
writing to mmc 1...
3758096384 bytes written in 142568 ms (25.1 MiB/s)
```

### Method 2: SD Card with gzwrite

```
=> mmc dev 0
=> ls mmc 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### Method 3: TFTP Network Boot

If you have a TFTP server:

```
=> setenv serverip 192.168.1.100
=> setenv ipaddr 192.168.1.50
=> setenv loadaddr 0x1000000
=> tftpboot $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### Method 4: Raw mmc write (Uncompressed)

For uncompressed `.img` files (slower, requires larger USB):

```
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img
=> mmc dev 1
=> mmc write $loadaddr 0 $filesize
```

**Note:** `mmc write` expects block count, not byte count. Calculate: `blocks = filesize / 512`

## Configure Boot Order

After flashing, set eMMC as primary boot:

```
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

=> reset
```

## U-Boot Device Reference

| Device | U-Boot | Linux | Description |
|--------|--------|-------|-------------|
| SD Card | `mmc 0` | `/dev/mmcblk0` | microSD slot |
| eMMC | `mmc 1` | `/dev/mmcblk1` | Internal eMMC |
| USB | `usb 0` | `/dev/sda` | USB storage |
| SPI NOR | `sf 0` | `/dev/mtd0` | U-Boot firmware |

## Network Interfaces (Linux)

ESPRESSObin uses a Marvell 88E6341 DSA switch:

| Interface | U-Boot | Linux | Role | IP (default) |
|-----------|--------|-------|------|--------------|
| eth0 | — | eth0 | WAN (upstream) | DHCP client |
| lan0 | — | lan0 | LAN port 1 | br-lan member |
| lan1 | — | lan1 | LAN port 2 | br-lan member |
| — | — | br-lan | LAN bridge | 192.168.1.1/24 |

## Troubleshooting

### USB Not Detected

```
=> usb reset
=> usb tree
=> usb info
```

Try different USB port or USB 2.0 drive (some USB 3.0 drives have issues).

### eMMC Not Detected

```
=> mmc list
mmc@d0000: 0 (SD)
mmc@d8000: 1 (eMMC)

=> mmc dev 1
=> mmc info
Device: mmc@d8000
Manufacturer ID: 15
OEM: 100
Name: 8GTF4
Bus Speed: 52000000
Mode: MMC High Speed (52MHz)
Capacity: 7.3 GiB
```

If `mmc dev 1` fails, the board may not have eMMC — use SD card.

### gzwrite Fails — Out of Memory

```
=> setenv loadaddr 0x1000000
```

For 1GB boards, ensure the image is compressed (`.img.gz`).

### Boot Fails — Wrong boot_targets

```
=> print boot_targets
boot_targets=mmc0 usb0 mmc1

=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
=> reset
```

### Reset U-Boot Environment

```
=> env default -a
=> saveenv
=> reset
```

### Check Environment

```
=> print
=> print bootcmd
=> print boot_targets
```

## Recovery — UART Boot

If U-Boot is corrupted:

1. Set DIP switches: SW1=ON, SW2=ON, SW3=OFF (UART boot mode)
2. Use `mvebu_xmodem` or `kwboot` to load U-Boot via serial
3. Flash new U-Boot to SPI NOR
4. Reset DIP switches to normal

```bash
# Linux recovery (requires kwboot)
sudo kwboot -t -b u-boot-espressobin.bin /dev/ttyUSB0 -B 115200
```

## Post-Installation

### Default Credentials

| User | Password |
|------|----------|
| root | secubox |
| secubox | secubox |

### First Steps

```bash
# Connect via serial or SSH
ssh root@192.168.1.1

# Change passwords
passwd root
passwd secubox

# Check status
secubox-status

# Access Web UI
# https://192.168.1.1:8443
```

### Verify Network

```bash
# Check interfaces
ip link show

# Check bridge
bridge link show

# Check IP addresses
ip addr show
```

## Performance Notes (ESPRESSObin vs MOCHAbin)

| Metric | ESPRESSObin v7 | MOCHAbin |
|--------|----------------|----------|
| CPU | 2× A53 @ 1.2GHz | 4× A72 @ 1.4GHz |
| RAM | 1-2 GB | 4 GB |
| Network | 3× GbE | 4× GbE + 2× 10GbE |
| DPI Mode | Passive only | Inline capable |
| CrowdSec | Lite mode | Full mode |
| SecuBox Profile | secubox-lite | secubox-full |

## See Also

- [[ARM-Installation]] — General ARM installation guide
- [[Installation]] — x86/VM installation
- [[Live-USB]] — Try without installing
- [[Modules]] — Available SecuBox modules
- [ESPRESSObin Wiki](http://wiki.espressobin.net/) — Official hardware wiki
- [Marvell Armada 3720](https://www.marvell.com/embedded-processors/armada-3700/) — SoC documentation
