# SecuBox U-Boot boot script for ESPRESSObin v7
# Marvell Armada 3720 with 88E6341 DSA switch + eMMC
# Compile with: mkimage -C none -A arm64 -T script -d boot.cmd boot.scr

echo "============================================"
echo "SecuBox ESPRESSObin v7 Boot"
echo "============================================"

# Detect boot device from U-Boot environment
# devtype/devnum set by distroboot; fallback to probing
if test -n "${devtype}" -a -n "${devnum}"; then
    echo "Boot device from env: ${devtype} ${devnum}"
    setenv bootdev "${devnum}"
else
    echo "Probing boot devices..."
    # ESPRESSObin v7: SD card = mmc0, eMMC = mmc1
    setenv bootdev 1
    echo "Using mmc 1 (eMMC)"
fi

setenv bootpart "mmc ${bootdev}:1"

# Use LABEL for reliable root device identification
# Device names (mmcblk0/mmcblk1) change based on what's connected
# LABEL=rootfs is always consistent
setenv rootpart "LABEL=rootfs"

echo "Boot partition: ${bootpart}"
echo "Root partition: ${rootpart}"

# Load kernel
echo "Loading kernel from ${bootpart}..."
if load ${bootpart} ${kernel_addr_r} Image; then
    echo "Kernel loaded OK"
else
    echo "ERROR: Failed to load kernel from ${bootpart}"
    # Try alternate device
    if test "${bootdev}" = "0"; then
        setenv bootdev 1
    else
        setenv bootdev 0
    fi
    setenv bootpart "mmc ${bootdev}:1"
    echo "Retrying with ${bootpart}..."
    load ${bootpart} ${kernel_addr_r} Image
fi

# Load DTB - try eMMC variant FIRST since we're booting from eMMC
# The v7-emmc DTB enables the second SDHCI controller (d00d8000) for eMMC
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded: armada-3720-espressobin-v7-emmc.dtb (eMMC enabled)"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-emmc.dtb; then
    echo "DTB loaded: armada-3720-espressobin-emmc.dtb (fallback eMMC)"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7.dtb; then
    echo "DTB loaded: armada-3720-espressobin-v7.dtb (WARNING: no eMMC support)"
else
    echo "ERROR: No compatible DTB found!"
    echo "Trying generic espressobin DTB..."
    load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin.dtb
fi

# Load initramfs (required for sdhci-xenon driver on eMMC)
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    echo "Initramfs loaded OK"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    echo "WARNING: No initramfs found - eMMC may not be detected!"
    setenv use_initrd 0
fi

# Set boot args
# rootdelay=5: give storage time to settle
# modprobe.blacklist: prevent mv88e6xxx DSA driver from loading during initramfs
# sdhci.debug_quirks2=0x40: fix xenon-sdhci DDR timing issues on eMMC
# mmc_core.use_spi_crc=0: disable CRC checks that can cause timeouts
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init sdhci.debug_quirks2=0x40"

echo "Boot args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
