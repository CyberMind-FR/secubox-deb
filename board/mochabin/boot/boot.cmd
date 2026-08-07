# SecuBox U-Boot boot script for MOCHAbin
# Marvell Armada 7040 with Topaz 88E6141/6341 switch
# Compile with: mkimage -C none -A arm64 -T script -d boot.cmd boot.scr
#
# Ce script COURT-CIRCUITE extlinux.conf (booti direct).
#
# POURQUOI IL A ETE REECRIT (#998)
#
# Il cherchait `Image-secubox-led` puis `Image` — deux fichiers ABSENTS de
# /boot. Les deux `load` echouaient donc, et le noyau reellement demarre ne
# correspondait a aucun de ceux qu'on deployait : `uname -v` annoncait une
# compilation du 2 juin alors que le noyau installe datait du jour meme.
# Consequence concrete : CONFIG_CFS_BANDWIDTH, compile EN DUR, n'arrivait
# jamais — et sept conteneurs declarant `lxc.cgroup2.cpu.max` refusaient de
# demarrer.
#
# Le DTB compte autant que le noyau : on charge `mpcie-fix`, celui
# qu'utilisait extlinux. Le DTB generique fait perdre le mPCIe, donc l'EP06 et
# l'USB — c'est-a-dire les supports externes.

echo "============================================"
echo "SecuBox MOCHAbin Boot (auto)"
echo "============================================"

setenv bootdev 0
setenv bootpart "mmc 0:1"
setenv rootpart "/dev/mmcblk0p2"

echo "Boot: ${bootpart} | Root: ${rootpart}"

# Noyau SecuBox courant, puis replis. L'ordre va du plus recent au plus sur :
# si le noyau du jour ne se charge pas, on retombe sur celui qui marchait.
echo "Loading kernel..."
if load ${bootpart} ${kernel_addr_r} Image-secubox-5; then
    echo "SecuBox kernel loaded (Image-secubox-5)"
    setenv initrd_file "initrd.img-6.12.85"
elif load ${bootpart} ${kernel_addr_r} Image-mpcie-fix; then
    echo "Fallback kernel loaded (Image-mpcie-fix)"
    setenv initrd_file "initrd.img-mpcie-fix"
elif load ${bootpart} ${kernel_addr_r} Image; then
    echo "Standard kernel loaded"
    setenv initrd_file "initrd.img"
else
    echo "ERROR: No kernel found!"
    exit
fi

# DTB : mpcie-fix d'abord — sans lui, plus de mPCIe (EP06, USB).
echo "Loading DTB..."
load ${bootpart} ${fdt_addr_r} armada-7040-mochabin-mpcie-fix.dtb || \
    load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-7040-mochabin.dtb || \
    load ${bootpart} ${fdt_addr_r} armada-7040-mochabin.dtb

echo "Loading initrd..."
if load ${bootpart} ${ramdisk_addr_r} ${initrd_file}; then
    setenv ramdisk_arg "${ramdisk_addr_r}:${filesize}"
    echo "Initrd loaded: ${filesize} bytes"
else
    setenv ramdisk_arg "-"
    echo "No initrd, booting without"
fi

setenv bootargs "root=${rootpart} rootfstype=ext4 rw rootwait console=ttyS0,115200 net.ifnames=0"

echo "Args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

booti ${kernel_addr_r} ${ramdisk_arg} ${fdt_addr_r}
