# MOCHAbin — SecuBox Installation Guide

## Hardware

- **SoC**: Marvell Armada 7040 (Cortex-A72 Quad-core 1.8GHz)
- **RAM**: 4 GB DDR4
- **Storage**: 8 GB eMMC + SATA + NVMe
- **Network**: 2x SFP+ 10GbE + 4x GbE + 10G RJ45
- **Profile**: SecuBox Full (all features enabled)

## Storage Limits

| Storage | Capacity | Notes |
|---------|----------|-------|
| eMMC | 8 GB | Primary boot device |
| SATA | Unlimited | Optional data storage |
| NVMe | Unlimited | High-speed storage |
| microSD | Up to 128GB | Backup boot option |

**Image size constraints:**
- Default image: **4GB** (fits 8GB eMMC with room for data)
- Maximum recommended: **6GB** (leaves 2GB for data/logs)
- SATA/NVMe can be used for `/data` partition

## Installation via U-Boot

### 1. Enter U-Boot

Connect serial console (115200 8N1) and power on. Press any key:

```
Hit any key to stop autoboot:  0
=>
```

### 2. Initialize USB

```
=> usb reset
=> usb storage
```

### 3. Flash to eMMC

```bash
# Set load address (4GB RAM available)
=> setenv loadaddr 0x1000000

# Load from USB (partition 1 or 4)
=> load usb 0:1 $loadaddr secubox-mochabin-bookworm.img.gz

# Write to eMMC with decompression
=> gzwrite mmc 1 $loadaddr $filesize
```

### 4. Configure Boot Order

```bash
=> setenv boot_targets "mmc1 scsi0 usb0 mmc0"
=> saveenv
=> reset
```

## Alternative: Flash to SATA

For larger installations, flash to SATA drive:

```bash
=> scsi scan
=> load usb 0:1 $loadaddr secubox-mochabin-bookworm.img.gz
=> gzwrite scsi 0 $loadaddr $filesize
```

## Boot Device Reference

| Device | U-Boot | Description |
|--------|--------|-------------|
| eMMC | `mmc 1` | 8GB internal (default) |
| SD Card | `mmc 0` | microSD slot |
| SATA | `scsi 0` | SATA drive |
| USB | `usb 0` | USB storage |

## Network Interfaces

| Interface | Role | Speed |
|-----------|------|-------|
| eth0 | WAN | 1 Gbps |
| eth1-eth4 | LAN | 1 Gbps |
| eth5, eth6 | SFP+ | 10 Gbps |

## Default Credentials

| User | Password |
|------|----------|
| root | secubox |
| secubox | secubox |

## Serial Console

```
Baud rate:    115200
Data bits:    8
Parity:       None
Stop bits:    1
```

```bash
screen /dev/ttyUSB0 115200
```

## Troubleshooting

### eMMC not detected
```
=> mmc list
=> mmc dev 1
=> mmc info
```

### SATA not detected
```
=> scsi scan
=> scsi info
```

### Check boot environment
```
=> print boot_targets
=> print fdtfile
```

## See Also

- [ARM Installation Wiki](https://github.com/CyberMind-FR/secubox-deb/wiki/ARM-Installation)
- [ESPRESSObin v7 Guide](../espressobin-v7/README.md)
