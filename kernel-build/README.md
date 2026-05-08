# SecuBox MOCHAbin Kernel Build

Custom Linux **6.6.x LTS** kernel for Marvell Armada 7040 (MOCHAbin) with OpenWrt-style built-in drivers.

> **Important**: Use kernel 6.6.x (same as OpenWrt) for reliable I2C/LED support.
> Kernel 6.12.x has mv64xxx I2C driver timing issues that cause LED write failures.

## Features

### Built-in Drivers (=y)

Critical boot drivers are built-in to avoid deferred probe issues:

| Category | Driver | Config |
|----------|--------|--------|
| **DSA** | mv88e6xxx switch | `CONFIG_NET_DSA_MV88E6XXX=y` |
| **Ethernet** | Marvell PPv2 | `CONFIG_MVPP2=y` |
| **PHY** | Marvell 1G/10G | `CONFIG_MARVELL_PHY=y`, `CONFIG_MARVELL_10G_PHY=y` |
| **Storage** | Xenon SDHCI (eMMC) | `CONFIG_MMC_SDHCI_XENON=y` |
| **Storage** | AHCI SATA | `CONFIG_AHCI_MVEBU=y` |
| **USB** | XHCI Host | `CONFIG_USB_XHCI_HCD=y` |
| **ComPHY** | CP110 PHY | `CONFIG_PHY_MVEBU_CP110_COMPHY=y` |

### Module Drivers (=m)

Drivers as modules for flexibility and recovery:

| Module | Purpose |
|--------|---------|
| `leds-is31fl319x` | **LED controller** (module allows I2C recovery) |
| `usbnet` | USB network framework |
| `cdc_ether` | CDC-ECM USB Ethernet |
| `cdc_ncm` | CDC-NCM USB Ethernet |
| `rndis_host` | RNDIS USB Ethernet |

> **Note**: LED driver is a module to allow recovery from I2C bus hangs:
> ```bash
> rmmod leds_is31fl319x && modprobe leds_is31fl319x
> ```

## Build Instructions

### Prerequisites

```bash
# Install cross-compiler
sudo apt install gcc-aarch64-linux-gnu

# Get kernel source
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.137.tar.xz
tar xf linux-6.6.137.tar.xz
cd linux-6.6.137
```

### Apply I2C/LED Patches

Apply patches to fix I2C timing issues with the IS31FL319X LED driver:

```bash
# From kernel source directory
cd linux-6.6.137

# Apply LED driver delay patch
patch -p1 < ../kernel-build/patches/001-leds-is31fl319x-add-i2c-delays.patch

# Apply I2C errata delay increase patch
patch -p1 < ../kernel-build/patches/002-i2c-mv64xxx-increase-errata-delay.patch
```

### Configuration

```bash
# Start with defconfig
make ARCH=arm64 defconfig

# Merge SecuBox fragment
scripts/kconfig/merge_config.sh -m .config \
    ../board/mochabin/kernel/config-6.12-openwrt-merged.fragment

# Finalize config
make ARCH=arm64 olddefconfig
```

### Build

```bash
# Build kernel (cross-compile for ARM64)
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)

# Output: arch/arm64/boot/Image
```

### Deploy

```bash
# Copy to MOCHAbin
scp arch/arm64/boot/Image root@C3BOX:/boot/Image-openwrt

# Update boot menu (already configured in extlinux.conf)
ssh root@C3BOX reboot
```

## Config Fragment

The main configuration is in:
```
board/mochabin/kernel/config-6.12-openwrt-merged.fragment
```

This fragment merges:
- OpenWrt MVEBU/Cortex-A72 kernel config (built-in drivers)
- Debian systemd compatibility requirements
- SecuBox-specific features (LED, USB network)

### Key Sections

1. **ARCHITECTURE** - ARM64 Cortex-A72, 4K pages, 39-bit VA
2. **MVEBU PLATFORM** - Armada 8K/7040, GIC-v3, clock/reset
3. **BOOT CRITICAL** - Storage (MMC, SATA), filesystems (ext4, FAT)
4. **NETWORK** - PPv2 Ethernet, DSA switch, PHYs
5. **USB HOST** - XHCI, EHCI, OHCI
6. **I2C/LED** - MV64XXX I2C, IS31FL319X LED
7. **SYSTEMD** - cgroups, namespaces, BPF, seccomp
8. **CRYPTO** - ChaCha20, AES, hardware CESA

## Boot Configuration

Extlinux boot menu at `/boot/extlinux/extlinux.conf`:

```
DEFAULT openwrt
TIMEOUT 50
PROMPT 1
MENU TITLE SecuBox MOCHAbin Boot Menu

LABEL openwrt
    MENU LABEL 1. OpenWrt-style Kernel (DSA built-in)
    KERNEL /Image-openwrt
    FDT /armada-7040-mochabin-openwrt.dtb
    APPEND root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait console=ttyS0,115200
```

## LED Hardware

MOCHAbin has 9 RGB LEDs controlled by an IS31FL3199 chip:
- **Bus:** I2C-1
- **Address:** 0x64
- **Driver:** `leds-is31fl319x`

After boot, LEDs should appear at:
```bash
ls /sys/class/leds/
# is31fl3199:led0 ... is31fl3199:led8
```

## Troubleshooting

### DSA switch not working
- Ensure `CONFIG_NET_DSA_MV88E6XXX=y` (not =m)
- Check dmesg for `mv88e6xxx` probe messages

### LEDs not appearing
- Check I2C bus: `i2cdetect -y 1` (should show 0x64)
- Check driver loaded: `dmesg | grep is31fl`
- Verify DTS has correct node

### LED I2C errors (-EIO)

Symptoms:
```
leds green:led1: Setting an LED's brightness failed (-5)
```

The mv64xxx I2C driver on Marvell Armada platforms has timing issues (errata FE-8471889).
The mainline kernel has a 5µs delay fix, but this is sometimes insufficient for LED controllers.

**Solution**: Apply the patches in `kernel-build/patches/`:

1. `001-leds-is31fl319x-add-i2c-delays.patch` - Adds 1ms delays between I2C writes in LED driver
2. `002-i2c-mv64xxx-increase-errata-delay.patch` - Increases errata delay from 5µs to 50µs

After patching and rebuilding the kernel, LED timer triggers should work without errors.

**Alternative workaround** (without kernel rebuild):
Use slow kernel timers (2-4 second cycles) via `secubox-led-trigger` script instead of
rapid userspace updates. The slow timers give the I2C bus time to settle between writes.

### USB network not working
- Load modules: `modprobe cdc_ether`
- Check dmesg when plugging Eye Remote

## Related Issues

- GitHub Issue #60: Kernel build tracking
- GitHub Issue #45: IS31FL3199 driver
- GitHub Issue #39: LED heartbeat port

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
