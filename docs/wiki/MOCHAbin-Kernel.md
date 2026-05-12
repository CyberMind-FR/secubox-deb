<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MOCHAbin Kernel — LED & Hardware Support

*SecuBox kernel configuration for GlobalScale MOCHAbin (Armada 7040)*

---

## Hardware Overview

| Component | Chip | Kernel Driver | Address |
|-----------|------|--------------|---------|
| **LED Controller** | IS31FL3199 | `leds-is31fl319x` | I2C-1 `0x64` |
| **Network PPv2.2** | Marvell PPv2 | `mvpp2` | Built-in |
| **I2C Bus** | MV64XXX | `i2c-mv64xxx` | CP0 |
| **eMMC** | Xenon | `mmc_sdhci_xenon` | CP0 |
| **SFP Cage** | PHY/SFP | `sfp` + `phylink` | eth2 |

---

## Build Strategy

### Why Debian Base + SecuBox Fragment?

Previous custom minimal configs caused **kernel panics** due to missing network drivers (`MVPP2`, `MVNETA`). The current approach:

1. **Start with Debian arm64 kernel config** — includes all working drivers
2. **Merge SecuBox fragment** — enables LED drivers as built-in (`=y`)
3. **Apply DTS patch** — fixes GPIO polarity for LED shutdown pin

```bash
# Build workflow
cd linux-6.12.85
cp config-6.12.85-debian-base .config
./scripts/kconfig/merge_config.sh -m .config config-6.12.85-secubox-led-v2.fragment
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) Image modules dtbs
```

---

## Config Files

### Debian Base Config

Location: `board/mochabin/kernel/config-6.12.85-debian-base`

Extracted from working Debian MOCHAbin system with:
```bash
zcat /proc/config.gz > config-6.12.85-debian-base
```

Key working drivers (already `=y` or `=m`):
- `CONFIG_MVPP2=m` — Marvell PPv2.2 Ethernet
- `CONFIG_MVNETA=m` — Marvell NETA Ethernet
- `CONFIG_MVMDIO=m` — Marvell MDIO bus
- `CONFIG_MARVELL_PHY=m` — PHY drivers
- `CONFIG_I2C_MV64XXX=m` — I2C controller

### SecuBox LED Fragment

Location: `board/mochabin/kernel/config-6.12.85-secubox-led-v2.fragment`

```
# LED Driver (IS31FL3199 on MOCHAbin)
CONFIG_LEDS_IS31FL319X=y
CONFIG_LEDS_IS31FL32XX=y
CONFIG_LEDS_CLASS=y
CONFIG_LEDS_CLASS_MULTICOLOR=y

# LED Triggers
CONFIG_LEDS_TRIGGERS=y
CONFIG_LEDS_TRIGGER_TIMER=y
CONFIG_LEDS_TRIGGER_HEARTBEAT=y
CONFIG_LEDS_TRIGGER_CPU=y
CONFIG_LEDS_TRIGGER_DEFAULT_ON=y
CONFIG_LEDS_TRIGGER_NETDEV=y

# I2C (for LED controller)
CONFIG_I2C_MV64XXX=y
CONFIG_I2C_CHARDEV=y
CONFIG_REGMAP_I2C=y

# Network (MOCHAbin PPv2.2)
CONFIG_MVPP2=y
CONFIG_MVMDIO=y
CONFIG_MVNETA=y
CONFIG_PHYLINK=y
CONFIG_FIXED_PHY=y
CONFIG_MARVELL_PHY=y
CONFIG_SFP=y

# MMC/eMMC (Xenon controller)
CONFIG_MMC_SDHCI_XENON=y

# GPIO (for LED shutdown pin)
CONFIG_GPIO_MVEBU=y
CONFIG_PINCTRL_MVEBU=y
CONFIG_PINCTRL_ARMADA_CP110=y
CONFIG_PINCTRL_ARMADA_AP806=y

# Debug: /proc/config.gz
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
```

---

## DTS Patch — GPIO Polarity Fix

### The Problem

The IS31FL3199 has a **SDB (shutdown bar)** pin that must be driven **HIGH** to enable the chip. The upstream kernel DTS incorrectly uses `GPIO_ACTIVE_LOW`, keeping the LED controller in permanent shutdown.

### The Fix

Location: `board/mochabin/patches/0001-fix-is31fl3199-led-gpio-polarity.patch`

```diff
--- a/arch/arm64/boot/dts/marvell/armada-7040-mochabin.dts
+++ b/arch/arm64/boot/dts/marvell/armada-7040-mochabin.dts
@@ -236,7 +236,7 @@
    #size-cells = <0>;
    pinctrl-names = "default";
    pinctrl-0 = <&is31_sdb_pins>;
-   shutdown-gpios = <&cp0_gpio1 30 GPIO_ACTIVE_LOW>;
+   shutdown-gpios = <&cp0_gpio1 30 GPIO_ACTIVE_HIGH>;
    reg = <0x64>;
```

### Upstream Status

This fix should be submitted to `linux-arm-kernel@lists.infradead.org` for inclusion. Similar devices in the kernel (`cn9130-cf-base.dts`, `cn9132-clearfog.dts`) already use `GPIO_ACTIVE_HIGH`.

---

## LED Hardware on MOCHAbin

### I2C Detection

```bash
$ i2cdetect -y 1
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:                         -- -- -- -- -- -- -- --
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
40: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
50: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
60: -- -- -- -- 64 -- -- -- -- -- -- -- -- -- -- --
70: -- -- -- -- -- -- -- --
```

### LED Mapping

| LED | Color | DTS Name | Usage |
|-----|-------|----------|-------|
| led1 | Red | `led@1` | Activity |
| led2 | Green | `led@2` | System |
| led3 | Blue | `led@3` | Network |
| led4-9 | RGB | `led@4-9` | Status |

### LED Control

```bash
# List available LEDs
ls /sys/class/leds/

# Set LED trigger
echo heartbeat > /sys/class/leds/led1_red/trigger

# Manual brightness
echo 255 > /sys/class/leds/led2_green/brightness

# Network activity trigger
echo netdev > /sys/class/leds/led3_blue/trigger
echo eth0 > /sys/class/leds/led3_blue/device_name
echo "rx tx" > /sys/class/leds/led3_blue/mode
```

---

## LOCALVERSION Branding

The kernel is built with:

```
LOCALVERSION=-secubox-cybermind
```

This produces a kernel version string like:
```
Linux secubox 6.12.85-secubox-cybermind #1 SMP PREEMPT Thu May 8 2026 aarch64
```

---

## Build Script

Location: `kernel-build/rebuild-with-leds.sh`

The script:
1. Copies Debian base config
2. Merges SecuBox LED fragment
3. Applies GPIO polarity DTS patch
4. Verifies critical options are built-in
5. Builds Image + DTB + modules
6. Creates `.deb` packages

```bash
./kernel-build/rebuild-with-leds.sh
```

Output files:
- `arch/arm64/boot/Image`
- `arch/arm64/boot/dts/marvell/armada-7040-mochabin.dtb`
- `linux-image-6.12.85-secubox-cybermind_*.deb`
- `linux-headers-6.12.85-secubox-cybermind_*.deb`

---

## Troubleshooting

### LED Not Working

1. **Check I2C detection**: `i2cdetect -y 1` should show `64`
2. **Check dmesg**: `dmesg | grep -i is31fl`
3. **Verify config**: `zcat /proc/config.gz | grep IS31FL`
4. **Check GPIO**: `gpioinfo | grep sdb`

### Network Panic

If network fails with panic:
- Verify `CONFIG_MVPP2=y` (must be built-in, not module)
- Verify `CONFIG_PHYLINK=y`
- Check DTB has correct MAC addresses

### Build Failures

```bash
# Missing cross-compiler
apt install gcc-aarch64-linux-gnu

# Missing dependencies
apt install build-essential libssl-dev bc bison flex libelf-dev

# Verify ARCH is set
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
```

---

## References

- [IS31FL3199 Datasheet](https://www.lumissil.com/assets/pdf/core/IS31FL3199_DS.pdf)
- [Marvell PPv2 Driver](https://docs.kernel.org/networking/device_drivers/ethernet/marvell/mvpp2.html)
- [MOCHAbin Wiki](https://wiki.solid-run.com/doku.php?id=products:mochabin:getting_started)
- [Linux LED Class](https://www.kernel.org/doc/html/latest/leds/leds-class.html)

---

*CyberMind — SecuBox-Deb · docs/wiki/MOCHAbin-Kernel.md*
