# SecuBox Live USB boot script for ESPRESSObin v7
# Marvell Armada 3720 — Boot from USB drive
# Compile with: mkimage -C none -A arm64 -T script -d boot-live-usb.cmd boot-live-usb.scr

echo "============================================"
echo "SecuBox ESPRESSObin v7 — Live USB Boot"
echo "============================================"

# USB boot: USB drive is typically usb 0:1
# Check if USB is available
usb start

setenv bootpart "usb 0:1"
echo "Boot partition: ${bootpart}"

# Live boot uses /dev/sda2 as root (USB drive)
# The kernel will find the SquashFS filesystem
setenv rootpart "/dev/sda2"
echo "Root partition: ${rootpart}"

# Load kernel
echo "Loading kernel from USB..."
if load ${bootpart} ${kernel_addr_r} boot/Image; then
    echo "Kernel loaded OK"
else
    # Try alternate path
    if load ${bootpart} ${kernel_addr_r} Image; then
        echo "Kernel loaded from root"
    else
        echo "ERROR: Failed to load kernel from USB!"
        echo "Make sure USB drive is properly formatted and connected."
        exit
    fi
fi

# Load DTB for v7-emmc (needed even for USB boot to detect eMMC)
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} boot/dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded: armada-3720-espressobin-v7-emmc.dtb"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded from root"
elif load ${bootpart} ${fdt_addr_r} boot/dtbs/marvell/armada-3720-espressobin-v7.dtb; then
    echo "DTB loaded: armada-3720-espressobin-v7.dtb"
else
    echo "ERROR: No compatible DTB found!"
    exit
fi

# Load initramfs
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} boot/initrd.img; then
    echo "Initramfs loaded OK"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
elif load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    echo "Initramfs loaded from root"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    echo "WARNING: No initramfs found!"
    setenv use_initrd 0
fi

# Set boot args for live boot
# boot=live: enable live-boot initramfs
# live-media-path: where to find filesystem.squashfs
# toram: optional, loads entire system to RAM (faster but uses more RAM)
# Blacklist mv88e6xxx switch driver - causes detection loop on ESPRESSObin
# modprobe.blacklist: for loadable modules
# initcall_blacklist: for built-in drivers
# Live boot: don't specify root= when using boot=live, let live-boot find squashfs
# live-media=/dev/sda2 tells live-boot which partition has the squashfs
setenv bootargs "boot=live live-media=/dev/sda2 live-media-path=/live toram console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init sdhci.debug_quirks2=0x40"

echo "Boot args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox Live USB..."
echo "============================================"

if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
