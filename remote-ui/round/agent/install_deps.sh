#!/bin/bash
# SecuBox Eye Remote - Install Python dependencies
# Run on Pi Zero W or mount SD card root

set -e

echo "=== SecuBox Eye Remote - Installing Dependencies ==="

# Check if running on Pi or mounted SD
if [ -d "/mnt/piroot" ]; then
    ROOT="/mnt/piroot"
    CHROOT="chroot $ROOT"
    echo "Installing to mounted SD card at $ROOT"
else
    ROOT=""
    CHROOT=""
    echo "Installing on local system"
fi

# Install system packages
$CHROOT apt-get update
$CHROOT apt-get install -y \
    python3-pip \
    python3-pil \
    python3-evdev \
    fonts-dejavu-core \
    fonts-liberation

# Install Python packages (if pip needed for any extras)
# evdev and Pillow should come from apt packages above

echo ""
echo "=== Dependencies installed ==="
echo "Required packages: python3-pil, python3-evdev"
