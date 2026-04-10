# SecuBox — Flash to eMMC from USB
# Run at U-Boot prompt: source $loadaddr
# Or: load usb 0:1 $loadaddr flash-emmc.scr && source $loadaddr

echo "============================================"
echo "SecuBox ESPRESSObin v7 — Flash to eMMC"
echo "============================================"

# Init USB
usb start
if usb dev 0; then
    echo "USB ready"
else
    echo "ERROR: Insert USB and retry"
    exit 1
fi

# Load compressed image
echo "Loading image..."
if load usb 0:1 ${loadaddr} secubox-espressobin-v7-bookworm.img.gz; then
    echo "Image loaded: ${filesize} bytes"
else
    echo "ERROR: Image not found on USB"
    echo "Expected: secubox-espressobin-v7-bookworm.img.gz"
    exit 1
fi

echo ""
echo "============================================"
echo "WARNING: This will ERASE eMMC!"
echo "Press Ctrl+C within 5 seconds to abort"
echo "============================================"
sleep 5

echo "Flashing to eMMC (mmc 1)..."
gzwrite mmc 1 ${loadaddr} ${filesize}

echo ""
echo "============================================"
echo "Flash complete!"
echo "Remove USB and type: reset"
echo "============================================"
