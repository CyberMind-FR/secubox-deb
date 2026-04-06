# SecuBox U-Boot boot script for ESPRESSObin Ultra
# Marvell Armada 3720 with 88E6341 DSA switch + eMMC
# Compile with: mkimage -C none -A arm64 -T script -d boot.cmd boot.scr

echo "============================================"
echo "SecuBox ESPRESSObin Ultra Boot"
echo "============================================"

# Detect boot device
if test -n "${devtype}" -a -n "${devnum}"; then
    echo "Boot device from env: ${devtype} ${devnum}"
    setenv bootdev "${devnum}"
else
    echo "Probing boot devices..."
    # ESPRESSObin Ultra: U-Boot eMMC = mmc1, Linux eMMC = mmcblk0
    setenv bootdev 1
    echo "Using mmc 1 (eMMC in U-Boot)"
fi

setenv bootpart "mmc ${bootdev}:1"
# IMPORTANT: Linux sees eMMC as mmcblk0 even though U-Boot sees it as mmc1
setenv rootpart "/dev/mmcblk0p2"

echo "Boot partition: ${bootpart}"
echo "Root partition: ${rootpart}"

# Load kernel
echo "Loading kernel..."
load ${bootpart} ${kernel_addr_r} Image

# Load DTB
echo "Loading device tree..."
# Try espressobin-ultra first, then v7-emmc as fallback
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-ultra.dtb; then
    echo "DTB: espressobin-ultra"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB: espressobin-v7-emmc (fallback)"
else
    echo "DTB: trying espressobin-emmc..."
    load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-emmc.dtb
fi

# Set boot args
# rootdelay=5: give storage time to settle
# mv88e6xxx.defer_ms=5000: delay DSA switch probe to prevent boot loop
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 mv88e6xxx.defer_ms=5000"

echo "Boot args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

booti ${kernel_addr_r} - ${fdt_addr_r}
