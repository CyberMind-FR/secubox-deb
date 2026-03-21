# board/mochabin/config.mk
# Configuration de build pour GlobalScale MOCHAbin
# SoC : Marvell Armada 7040 (Cortex-A72 Quad-core 1.8GHz)
# RAM : 4 GB DDR4 · eMMC : 8 GB · Réseau : 2× SFP+ 10GbE + 4× GbE + 10G RJ45

BOARD=mochabin
BOARD_SOC=armada-7040
ARCH=arm64
DEBIAN_ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

# Kernel
KERNEL_VERSION=6.6
KERNEL_DTS=armada-7040-mochabin
KERNEL_IMAGE=Image
KERNEL_DEFCONFIG=mvebu_v8_defconfig

# Kernel extra config pour SecuBox
KERNEL_EXTRAS=\
  CONFIG_MVNETA=y \
  CONFIG_MVPP2=y \
  CONFIG_NET_DSA=y \
  CONFIG_NET_DSA_MV88E6XXX=y \
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
  CONFIG_RANDOMIZE_BASE=y \
  CONFIG_STACKPROTECTOR_STRONG=y \
  CONFIG_FORTIFY_SOURCE=y \
  CONFIG_HARDENED_USERCOPY=y \
  CONFIG_SLAB_FREELIST_RANDOM=y \
  CONFIG_KASLR=y \
  CONFIG_SECURITY_APPARMOR=y

# U-Boot ATF (Armada 7040=a70x0)
UBOOT_DEFCONFIG=mvebu_mcbin-88f8040_defconfig
ATF_PLATFORM=a70x0
ATF_MARVELL_BRANCH=atf-v1.5-armada-18.12
# Binaires précompilés GlobalScale disponibles sur :
# https://github.com/MarvellEmbeddedProcessors/u-boot-marvell

# Profil SecuBox
SECUBOX_PROFILE=secubox-full
SECUBOX_LITE=0

# Interfaces réseau
WAN_IFACE=eth0
LAN_IFACES=eth1 eth2 eth3 eth4
SFP_IFACES=eth5 eth6

# RAM suffisante pour DPI full-line + toutes les fonctions
DPI_MODE=inline
SWAP_SIZE=0
