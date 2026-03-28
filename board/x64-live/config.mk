# board/x64-live/config.mk
# Configuration pour Live USB x64 (amd64)
# Compatible: Intel/AMD baremetal, VirtualBox, VMware, KVM/QEMU

BOARD=x64-live
BOARD_SOC=x86_64
ARCH=amd64
DEBIAN_ARCH=amd64

# Kernel (standard Debian amd64)
KERNEL_VERSION=6.1
KERNEL_IMAGE=vmlinuz
KERNEL_DEFCONFIG=

# Profil complet (RAM typiquement >= 4GB)
SECUBOX_PROFILE=secubox-full
SECUBOX_LITE=0

# Interfaces réseau - Auto-détection
# Le script secubox-net-detect identifie automatiquement:
# - WAN: première interface avec lien (DHCP)
# - LAN: autres interfaces (bridge br-lan)
WAN_IFACE=auto
LAN_IFACES=auto

# Mode réseau par défaut
# router: WAN DHCP + LAN bridge 192.168.1.1/24
# bridge: Toutes interfaces bridgées
# single: WAN seul, pas de LAN
NETMODE=router

# DPI inline sur x64 (RAM suffisante)
DPI_MODE=inline
SWAP_SIZE=0

# Live USB spécifique
LIVE_PERSISTENCE=yes
LIVE_KIOSK_MODE=optional
