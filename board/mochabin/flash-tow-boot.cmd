# SecuBox :: Tow-Boot Flash Script for MOCHAbin
# Run from U-Boot: fatload mmc 0:1 0x1000000 flash-tow-boot.scr && source 0x1000000

echo "============================================"
echo "SecuBox Tow-Boot Flash Script"
echo "MOCHAbin Armada 7040"
echo "============================================"
echo ""

# Configuration
setenv towboot_file tow-boot/Tow-Boot.spi.bin

echo "Flashing Tow-Boot using bubt command..."
echo "Source: mmc 0:1 ${towboot_file}"
echo "Target: SPI flash"
echo ""

# bubt <filename> <dest> <source>
# dest: spi = SPI NOR flash
# source: mmc = load from MMC/eMMC
bubt ${towboot_file} spi mmc

echo ""
echo "=========================================="
echo "Flash complete. Resetting..."
echo "=========================================="
reset
