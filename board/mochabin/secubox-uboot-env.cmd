# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox U-Boot — préparation de l'environnement, MOCHAbin (#3271, modèle #2826).
# FICHIER GÉNÉRÉ par packages/secubox-netboot/scripts/uboot-env.py depuis
#   packages/secubox-netboot/board/mochabin/live.env et uboot-env.env : ne pas l'éditer à la main.
# Compile : mkimage -A arm64 -O linux -T script -C none -n "SecuBox uboot env" -d secubox-uboot-env.cmd secubox-uboot-env.scr
#
# Pose, puis enregistre (saveenv) :
#   - adresses sûres : kernel_addr_r 0x08000000, fdt_addr_r 0x0c000000, ramdisk_addr_r 0x0c100000 ;
#   - ethact mvpp2-2 (port WAN) et autoload no (le dhcp ne charge rien) ;
#   - bootcmd : démarrage depuis le support installé (mmc 0) ;
#   - bootcmd_netboot : secours netboot, JAMAIS lancé seul (un DHCP du WAN ne doit pas pouvoir démarrer la
#     box). À la console : setenv serverip <IP du maître>; run bootcmd_netboot
#     (sans setenv, serverip vient du next-server du DHCP, s'il en donne un) ;
#   - l'ancien bootcmd dans bootcmd_avant, au premier passage seulement.
#
# Lancer, au choix (console série 115200 8N1, compte à rebours interrompu), puis : reset
#   réseau    : setenv ethact mvpp2-2; setenv autoload no; dhcp; setenv serverip <IP du maître>; tftpboot ${loadaddr} mochabin-live/secubox-uboot-env.scr; source ${loadaddr}
#   clé USB   : usb start; fatload usb 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}
#   installée : mmc dev 0; fatload mmc 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}

echo "============================================"
echo "SecuBox MOCHAbin - preparation environnement U-Boot"
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
setenv bootcmd_netboot 'setenv ethact mvpp2-2; setenv autoload no; dhcp; tftpboot ${loadaddr} mochabin-live/boot.scr; source ${loadaddr}'
setenv bootcmd 'setenv ethact mvpp2-2; dhcp; mmc dev 0; fatload mmc 0:1 ${loadaddr} boot.scr; source ${loadaddr}'
saveenv

echo "Pose : adresses, ethact mvpp2-2, autoload no, bootcmd (mmc 0), bootcmd_netboot."
echo "Ancien bootcmd garde dans bootcmd_avant."
echo "Secours netboot : setenv serverip IP_DU_MAITRE; run bootcmd_netboot"
echo "Revenir en arriere : setenv bootcmd \"\${bootcmd_avant}\"; saveenv"
echo "Redemarrer : reset"
