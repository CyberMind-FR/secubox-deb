# SecuBox U-Boot boot script for ESPRESSObin v7 — USB Boot
# Boot from USB then optionally flash to eMMC
# Compile: mkimage -C none -A arm64 -T script -d boot-usb.cmd boot-usb.scr
#
# DEMARRER DEPUIS LA CLE USB — UNE LIGNE, a la console serie (115200 8N1), au prompt « Marvell>> » (Entree pendant le compte a rebours) :
#   usb start; load usb 0:1 ${loadaddr} boot-usb.scr; source ${loadaddr}
# Pour que la carte demarre TOUJOURS sur la cle USB quand elle est branchee (une seule fois) :
#   setenv bootcmd 'usb start; load usb 0:1 ${loadaddr} boot-usb.scr && source ${loadaddr}; run distro_bootcmd'; saveenv
# La racine est designee par son ETIQUETTE (rootfs) : le nom du disque (sda, sdb...) change selon le port USB.

echo "============================================"
echo "SecuBox ESPRESSObin v7 — USB Boot"
echo "============================================"

# Initialize USB
echo "Initializing USB..."
usb start

# Check for USB device
if usb dev 0; then
    echo "USB device found"
else
    echo "ERROR: No USB device found!"
    echo "Please insert USB drive and retry"
    exit 1
fi

# Check for compressed image (for gzwrite to eMMC)
echo "Checking for flash image..."
if load usb 0:1 ${loadaddr} secubox-espressobin-v7-bookworm.img.gz; then
    echo ""
    echo "============================================"
    echo "Found SecuBox image for eMMC flash!"
    echo "To flash to eMMC, run:"
    echo "  gzwrite mmc 1 \${loadaddr} \${filesize}"
    echo "  reset"
    echo "============================================"
    echo ""
    echo "Or continue USB boot (10s timeout)..."
    sleep 10
fi

# Load kernel from USB
echo "Loading kernel from USB..."
if load usb 0:1 ${kernel_addr_r} Image; then
    echo "Kernel loaded OK"
elif load usb 0:2 ${kernel_addr_r} boot/Image; then
    echo "Kernel loaded from boot/"
else
    echo "ERROR: Failed to load kernel"
    exit 1
fi

# Load DTB
echo "Loading device tree..."
if load usb 0:1 ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded: v7-emmc variant"
elif load usb 0:2 ${fdt_addr_r} boot/dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded from boot/"
elif load usb 0:1 ${fdt_addr_r} armada-3720-espressobin-v7-emmc.dtb; then
    echo "DTB loaded from root"
else
    echo "ERROR: No DTB found"
    exit 1
fi

# Load initramfs (optional)
echo "Loading initramfs..."
if load usb 0:1 ${ramdisk_addr_r} initrd.img; then
    echo "Initramfs loaded"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
elif load usb 0:2 ${ramdisk_addr_r} boot/initrd.img; then
    echo "Initramfs loaded from boot/"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    echo "No initramfs — booting without"
    setenv use_initrd 0
fi

# La racine est la partition etiquetee « rootfs » (initramfs : resolution par LABEL)
# Blacklist mv88e6xxx switch driver - causes detection loop on ESPRESSObin
setenv bootargs "root=LABEL=rootfs rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core,ath10k_pci,ath10k_core transparent_hugepage=never initcall_blacklist=mv88e6xxx_driver_init"

echo "============================================"
echo "Booting SecuBox from USB..."
echo "Boot args: ${bootargs}"
echo "============================================"

if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
