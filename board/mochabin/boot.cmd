# SecuBox U-Boot boot script for MOCHAbin
# Marvell Armada 7040 with Topaz 88E6141/6341 switch
# Compile with: mkimage -C none -A arm64 -T script -d boot.cmd boot.scr

echo "============================================"
echo "SecuBox MOCHAbin Boot"
echo "============================================"

# Detect boot device
if test -n "${devtype}" -a -n "${devnum}"; then
    echo "Boot device from env: ${devtype} ${devnum}"
    setenv bootdev "${devnum}"
else
    echo "Probing boot devices..."
    # MOCHAbin: eMMC=mmc0, SD=mmc1 (opposite of ESPRESSObin)
    if test -e mmc 0:1 Image; then
        setenv bootdev 0
        echo "Found boot on mmc 0 (eMMC)"
    elif test -e mmc 1:1 Image; then
        setenv bootdev 1
        echo "Found boot on mmc 1 (SD)"
    else
        echo "WARN: No Image found, trying mmc 0"
        setenv bootdev 0
    fi
fi

setenv bootpart "mmc ${bootdev}:1"
setenv rootpart "/dev/mmcblk${bootdev}p2"

echo "Boot partition: ${bootpart}"
echo "Root partition: ${rootpart}"

# Load kernel
echo "Loading kernel..."
if load ${bootpart} ${kernel_addr_r} Image; then
    echo "Kernel loaded OK"
else
    echo "ERROR: Failed to load kernel"
    if test "${bootdev}" = "0"; then
        setenv bootdev 1
    else
        setenv bootdev 0
    fi
    setenv bootpart "mmc ${bootdev}:1"
    setenv rootpart "/dev/mmcblk${bootdev}p2"
    echo "Retrying with ${bootpart}..."
    load ${bootpart} ${kernel_addr_r} Image
fi

# Load DTB
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-7040-mochabin.dtb; then
    echo "DTB loaded OK"
else
    echo "Trying alternate DTB path..."
    load ${bootpart} ${fdt_addr_r} armada-7040-mochabin.dtb
fi

# Set boot args
# rootdelay=5: give storage time to settle
# mv88e6xxx.defer_ms=5000: delay DSA switch probe
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 mv88e6xxx.defer_ms=5000"

echo "Boot args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

booti ${kernel_addr_r} - ${fdt_addr_r}
