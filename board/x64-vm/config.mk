# board/x64-vm/config.mk
# Configuration pour VM x64 (VirtualBox, VMware, KVM/QEMU, Proxmox)
# Utilisé pour les tests et environnements virtualisés

BOARD=x64-vm
BOARD_SOC=x86_64
ARCH=amd64
DEBIAN_ARCH=amd64

KERNEL_VERSION=6.1
KERNEL_IMAGE=vmlinuz

SECUBOX_PROFILE=secubox-full
SECUBOX_LITE=0

# Interfaces VM typiques
# VirtualBox: enp0s3 (NAT), enp0s8 (Host-only)
# KVM/libvirt: enp1s0 (bridge), enp2s0 (isolated)
# VMware: ens192, ens224
WAN_IFACE=auto
LAN_IFACES=auto

NETMODE=router
DPI_MODE=inline
SWAP_SIZE=0
