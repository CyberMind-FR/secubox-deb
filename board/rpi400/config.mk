# SecuBox board config - Raspberry Pi 400
# Pi 400 is essentially a Pi 4 with integrated keyboard

BOARD_NAME="Raspberry Pi 400"
BOARD_ARCH="arm64"
DEBIAN_ARCH="arm64"

# Image size (8G for USB boot with persistence)
IMG_SIZE="8G"
ROOT_SIZE="6G"
DATA_SIZE="1.5G"

# Boot type: pi (native Raspberry Pi bootloader)
BOOT_TYPE="pi"

# Has native USB 3.0 boot support
USB_BOOT=1

# Use build-rpi-usb.sh instead of build-image.sh
USE_RPI_SCRIPT=1

# Kernel: Debian arm64 kernel works great on Pi 400
KERNEL_PKG="linux-image-arm64"

# Required firmware
FIRMWARE_PKGS="raspi-firmware firmware-brcm80211"

# Network: eth0 (USB-C ethernet) + wlan0 (built-in WiFi)
NETWORK_INTERFACES="eth0 wlan0"
