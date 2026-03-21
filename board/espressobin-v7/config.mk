# board/espressobin-v7/config.mk
# Configuration pour GlobalScale ESPRESSObin v7
# SoC : Marvell Armada 3720 (Cortex-A53 Dual-core 1.2GHz)
# RAM : 1-2 GB DDR4 · eMMC optionnel / SD · Réseau : 1× WAN GbE + 2× LAN (88E6341 DSA)

BOARD=espressobin-v7
BOARD_SOC=armada-3720
ARCH=arm64
DEBIAN_ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

# Kernel
KERNEL_VERSION=6.6
KERNEL_DTS=armada-3720-espressobin-v7
KERNEL_IMAGE=Image
KERNEL_DEFCONFIG=mvebu_v8_defconfig

# Mêmes extras que mochabin sauf mvpp2
KERNEL_EXTRAS=\
  CONFIG_MVNETA=y \
  CONFIG_NET_DSA=y \
  CONFIG_NET_DSA_MV88E6XXX=y \
  CONFIG_WIREGUARD=y \
  CONFIG_NF_TABLES=y \
  CONFIG_NFT_CT=y \
  CONFIG_NFT_NAT=y \
  CONFIG_NET_CLS_FLOWER=y \
  CONFIG_NET_ACT_MIRRED=y \
  CONFIG_IFB=y \
  CONFIG_NET_SCH_HTB=y \
  CONFIG_NET_SCH_INGRESS=y \
  CONFIG_RANDOMIZE_BASE=y \
  CONFIG_STACKPROTECTOR_STRONG=y \
  CONFIG_FORTIFY_SOURCE=y \
  CONFIG_SECURITY_APPARMOR=y

# U-Boot ATF (Armada 3720)
UBOOT_DEFCONFIG=mvebu_espressobin-88f3720_defconfig
ATF_PLATFORM=a3700

# Profil Lite (RAM limitée 1-2 GB)
SECUBOX_PROFILE=secubox-lite
SECUBOX_LITE=1

# Interfaces (DSA switch 88E6341)
# lan0, lan1=ports LAN du switch ; eth0=WAN
WAN_IFACE=eth0
LAN_IFACES=lan0 lan1

# DPI passif uniquement sur ESPRESSObin (RAM insuffisante pour inline)
DPI_MODE=passive
# Swap activé pour ESPRESSObin 1GB
SWAP_SIZE=512M
