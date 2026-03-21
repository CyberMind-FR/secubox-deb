# board/vm-arm64/config.mk
# Configuration de build pour VM QEMU arm64
# Cible de test et développement ARM64

BOARD=vm-arm64
BOARD_SOC=arm64-virt
ARCH=arm64
DEBIAN_ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

# Kernel (utiliser le kernel Debian stock arm64)
KERNEL_VERSION=6.1
KERNEL_IMAGE=vmlinuz
KERNEL_INITRD=initrd.img
KERNEL_DEFCONFIG=defconfig
USE_STOCK_KERNEL=1

# Kernel extras pour QEMU virt machine
KERNEL_EXTRAS=\
  CONFIG_VIRTIO=y \
  CONFIG_VIRTIO_PCI=y \
  CONFIG_VIRTIO_MMIO=y \
  CONFIG_VIRTIO_NET=y \
  CONFIG_VIRTIO_BLK=y \
  CONFIG_VIRTIO_CONSOLE=y \
  CONFIG_VIRTIO_BALLOON=y \
  CONFIG_PCI_HOST_GENERIC=y \
  CONFIG_WIREGUARD=y \
  CONFIG_NF_TABLES=y \
  CONFIG_NFT_CT=y \
  CONFIG_NFT_LOG=y \
  CONFIG_NFT_LIMIT=y \
  CONFIG_NFT_NAT=y \
  CONFIG_NET_CLS_FLOWER=y \
  CONFIG_NET_ACT_MIRRED=y \
  CONFIG_IFB=y \
  CONFIG_NET_SCH_HTB=y \
  CONFIG_NET_SCH_INGRESS=y \
  CONFIG_SECURITY_APPARMOR=y

# Bootloader (GRUB EFI pour QEMU UEFI)
BOOTLOADER=grub-efi
GRUB_PLATFORM=arm64-efi
EFI_BOOT=/EFI/BOOT/BOOTAA64.EFI

# QEMU spécifique
QEMU_MACHINE=virt
QEMU_CPU=cortex-a72
QEMU_MIN_RAM=2048
QEMU_MIN_CPUS=2

# Profil SecuBox
SECUBOX_PROFILE=secubox-full
SECUBOX_LITE=0

# Interfaces réseau QEMU virtio
WAN_IFACE=enp0s1
LAN_IFACES=enp0s2
EXTRA_IFACES=

# DPI en mode passif pour VM
DPI_MODE=passive
SWAP_SIZE=1G

# Image formats
IMG_FORMATS=qcow2 raw
