<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MOCHAbin — SecuBox Installation Guide

## Hardware

- **SoC**: Marvell Armada 7040 (Cortex-A72 Quad-core 1.8GHz)
- **RAM**: 2GB / 4GB / 8GB DDR4 (variants)
- **Storage**: 16 GB eMMC + SATA + NVMe
- **Network**: 2x SFP+ 10GbE + 4x GbE + 10G RJ45
- **Profile**: SecuBox Full (all features enabled)

**Note**: MOCHAbin does NOT have a microSD slot.

## Boot Mode Jumpers (J17-J22)

The MOCHAbin uses 6 jumpers (J17-J22) to select boot mode. Each jumper can be:
- **R** (Right): pins 1-2 = 3.3V = "1"
- **L** (Left): pins 2-3 = GND = "0"

### Boot Mode Table

| Mode | Code | J17 | J18 | J19 | J20 | J21 | J22 | Description |
|------|------|-----|-----|-----|-----|-----|-----|-------------|
| SPI NOR | 0x32 | L | R | L | L | R | R | Default - Boot from SPI flash |
| eMMC (CP) | 0x2B | R | R | L | R | L | R | Boot from eMMC |
| UART | fallback | - | - | - | - | - | - | Fallback after boot failure |

### Jumper Change Summary

**SPI (0x32) → eMMC (0x2B)**: Change 3 jumpers:
| Jumper | From | To |
|--------|------|-----|
| J17 | L (2-3) | R (1-2) |
| J20 | L (2-3) | R (1-2) |
| J21 | R (1-2) | L (2-3) |

## Bootloader: Tow-Boot

SecuBox uses a custom Tow-Boot build with eMMC boot partition support.

### Building Tow-Boot

```bash
cd tools/Tow-Boot
sg nix-users -c "nix-build -A globalscale-mochabin-8gb"

# Output files in:
# tools/Tow-Boot/output/
#   Tow-Boot.spi.bin      - For SPI flash
#   Tow-Boot.mmcboot.bin  - For eMMC boot partition
#   Tow-Boot.noenv.bin    - Without environment storage
```

### Flashing via UART Recovery

If SPI is corrupt or empty, use UART boot:

```bash
# Install mvebu64boot tool
# Then power cycle board and run:
sudo mvebu64boot -t -b tools/Tow-Boot/output/Tow-Boot.spi.bin /dev/ttyUSB0
```

### Flashing to SPI (Primary Method)

In U-Boot console:
```
usb start
load usb 0:1 $loadaddr Tow-Boot.spi.bin

sf probe
sf erase 0 0x400000
sf write $loadaddr 0 $filesize

reset
```

### Flashing to eMMC Boot Partition

If SPI is dead, use eMMC boot:

```
usb start
load usb 0:1 $loadaddr Tow-Boot.mmcboot.bin

# Write to eMMC boot partition 1
mmc dev 0 1
mmc write $loadaddr 0 0xb80

# Configure boot from partition 1
mmc bootbus 0 1 0 0
mmc partconf 0 1 1 0

reset
```

Then set jumpers to eMMC boot mode (0x2B).

## Known Hardware Issues

### SPI Flash Intermittent (JEDEC 00,00,00)

Some boards have unreliable SPI NOR flash:
- `sf probe` returns "unrecognized JEDEC id bytes: 00, 00, 00"
- May work intermittently after power cycling
- **Fix**: Replace SPI flash chip (Winbond W25Q32, SOIC-8)

### eMMC BootROM Communication Failure

Some boards fail eMMC boot at BootROM level:
- Error: `Error interrupt: 00018000` / `Failed 00000061`
- U-Boot can access eMMC, but BootROM cannot
- **Workaround**: Use SPI boot or UART boot

## Storage Configuration

| Storage | Capacity | Notes |
|---------|----------|-------|
| eMMC | 16 GB | Primary boot device |
| SATA | Unlimited | Data storage |
| NVMe | Unlimited | High-speed storage |

**Image size**: 4GB default (fits eMMC with room for data)

## Installation via U-Boot

### 1. Enter U-Boot

Connect serial console (115200 8N1) and power on. Press ESC:

```
Please press [ESCAPE] or [CTRL+C] to enter the boot menu.
```

### 2. Flash SecuBox Image

```bash
usb start
load usb 0:1 $loadaddr secubox-mochabin-bookworm.img.gz

# Write to eMMC user area
gzwrite mmc 0 $loadaddr $filesize
```

### 3. Boot

```
reset
```

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
minicom -D /dev/ttyUSB0 -b 115200
# or
screen /dev/ttyUSB0 115200
```

## Troubleshooting

### eMMC not detected
```
mmc list
mmc dev 0
mmc info
```

### SPI flash not detected
```
sf probe
sf probe 0:0 1000000
```

### Check boot partition config
```
mmc partconf 0
```

### UART Recovery
```bash
# On host PC, then power cycle board:
sudo mvebu64boot -t -b Tow-Boot.spi.bin /dev/ttyUSB0
```

## See Also

- [Tow-Boot Source](../../tools/Tow-Boot/)
- [ESPRESSObin v7 Guide](../espressobin-v7/README.md)
- [ARM Installation Wiki](https://github.com/CyberMind-FR/secubox-deb/wiki/ARM-Installation)
