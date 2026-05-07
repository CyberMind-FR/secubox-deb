# SecuBox U-Boot boot script for MOCHAbin
# Marvell Armada 7040 with Topaz 88E6141/6341 switch
# Compile with: mkimage -C none -A arm64 -T script -d boot.cmd boot.scr
#
# This script provides automatic boot without menu selection.
# It bypasses extlinux.conf for direct kernel boot.

echo "============================================"
echo "SecuBox MOCHAbin Boot (auto)"
echo "============================================"

# MOCHAbin: eMMC=mmc0, SD=mmc1
setenv bootdev 0
setenv bootpart "mmc 0:1"
setenv rootpart "/dev/mmcblk0p2"

echo "Boot: ${bootpart} | Root: ${rootpart}"

# Try LED kernel first, fall back to standard
echo "Loading kernel..."
if load ${bootpart} ${kernel_addr_r} Image-secubox-led; then
    echo "LED kernel loaded"
    setenv initrd_file "initrd.img-6.12.85+deb12-arm64"
elif load ${bootpart} ${kernel_addr_r} Image; then
    echo "Standard kernel loaded"
    setenv initrd_file "initrd.img"
else
    echo "ERROR: No kernel found!"
    exit
fi

# Load DTB
echo "Loading DTB..."
load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-7040-mochabin.dtb || \
    load ${bootpart} ${fdt_addr_r} armada-7040-mochabin.dtb

# Load initrd
echo "Loading initrd..."
if load ${bootpart} ${ramdisk_addr_r} ${initrd_file}; then
    setenv ramdisk_arg "${ramdisk_addr_r}:${filesize}"
    echo "Initrd loaded: ${filesize} bytes"
else
    setenv ramdisk_arg "-"
    echo "No initrd, booting without"
fi

# Set boot args - console=ttyS0 for MOCHAbin
setenv bootargs "root=${rootpart} rootfstype=ext4 rw rootwait console=ttyS0,115200 net.ifnames=0"

echo "Args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

booti ${kernel_addr_r} ${ramdisk_arg} ${fdt_addr_r}
