# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox U-Boot — pose le `bootcmd` de la MOCHAbin après une installation sur l'eMMC (#3271, modèle ESPRESSObin #2826)
# Compile : mkimage -A arm64 -O linux -T script -C none -n "SecuBox fix bootcmd" -d fix-bootcmd.cmd fix-bootcmd.scr
#
# POURQUOI. Le U-Boot d'usine Marvell garde son bootcmd TFTP/NFS : après l'installation, la carte ne démarre pas seule
# sur l'eMMC. Trois corrections, enregistrées par saveenv :
#   1. bootcmd : port WAN cuivre (mvpp2-2) puis DHCP, puis boot.scr de l'eMMC (commande validée à la main). Le port
#      n'est initialisé pour Linux que si U-Boot l'a touché : sans ce DHCP, le système démarré de l'eMMC n'a pas de
#      réseau. Le « ; » laisse le démarrage continuer si le DHCP échoue. autoload=no : dhcp ne tente aucun TFTP.
#   2. Adresses #3091, au-dessus de la zone réservée 0x04000000-0x053fffff (PSCI + TEE) : un boot.scr d'avant #3091 ne
#      les pose pas, et l'usine a ramdisk_addr_r=- (l'initrd n'était pas chargé).
#   3. L'ancien bootcmd est gardé dans bootcmd_avant (seulement au premier passage : un second ne l'écrase pas).
#
# UNE LIGNE, à la console série du U-Boot (115200 8N1, Entrée au compte à rebours) :
#   fatload mmc 0:1 ${loadaddr} fix-bootcmd.scr; source ${loadaddr}

echo "============================================"
echo "SecuBox MOCHAbin — fix bootcmd (#3271)"
echo "============================================"
echo "bootcmd actuel : ${bootcmd}"

if test -z "${bootcmd_avant}"; then
    setenv bootcmd_avant "${bootcmd}"
fi
setenv kernel_addr_r 0x08000000
setenv fdt_addr_r 0x0c000000
setenv ramdisk_addr_r 0x0c100000
setenv ethact mvpp2-2
setenv autoload no
setenv bootcmd 'setenv ethact mvpp2-2; dhcp; mmc dev 0; fatload mmc 0:1 ${loadaddr} boot.scr; source ${loadaddr}'
saveenv

echo "bootcmd pose : WAN mvpp2-2 + DHCP, puis boot.scr de l'eMMC. Ancien bootcmd garde dans bootcmd_avant."
echo "Revenir en arriere : setenv bootcmd \"\${bootcmd_avant}\"; saveenv"
echo "(adresses d'usine : kernel_addr_r 0x7000000, fdt_addr_r 0x6f00000, ramdisk_addr_r -)"
echo "Redemarrer : reset"
