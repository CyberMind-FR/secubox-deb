# board/vm-x64/config.mk
# Configuration de build pour VM VirtualBox/QEMU/VMware x86_64
# Cible de test et développement

BOARD=vm-x64
BOARD_SOC=x86_64-generic
ARCH=x86_64
DEBIAN_ARCH=amd64
CROSS_COMPILE=

# Kernel (utiliser le kernel Debian stock)
KERNEL_VERSION=6.1
KERNEL_IMAGE=vmlinuz
KERNEL_INITRD=initrd.img
KERNEL_DEFCONFIG=x86_64_defconfig
USE_STOCK_KERNEL=1

# Kernel extra config pour SecuBox
KERNEL_EXTRAS=\
  CONFIG_VIRTIO=y \
  CONFIG_VIRTIO_PCI=y \
  CONFIG_VIRTIO_NET=y \
  CONFIG_VIRTIO_BLK=y \
  CONFIG_VIRTIO_CONSOLE=y \
  CONFIG_VIRTIO_BALLOON=y \
  CONFIG_E1000=y \
  CONFIG_E1000E=y \
  CONFIG_VMXNET3=y \
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

# Bootloader (GRUB pour UEFI)
BOOTLOADER=grub-efi
GRUB_PLATFORM=x86_64-efi
EFI_BOOT=/EFI/BOOT/BOOTX64.EFI

# VirtualBox spécifique
VBOX_GUEST_ADDITIONS=1
VBOX_MIN_RAM=2048
VBOX_MIN_CPUS=2

# Profil SecuBox
SECUBOX_PROFILE=secubox-full
SECUBOX_LITE=0

# Interfaces réseau VirtualBox (adapter le nombre selon config)
WAN_IFACE=enp0s3
LAN_IFACES=enp0s8
EXTRA_IFACES=

# Pour test, DPI en mode passif
DPI_MODE=passive
SWAP_SIZE=1G

# Image formats
IMG_FORMATS=vdi raw
