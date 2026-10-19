# SecuBox U-Boot — fixe le `bootcmd` de l'ESPRESSObin v7 : eMMC d'abord, puis la cle USB
# Compile : mkimage -C none -A arm64 -T script -d fix-bootcmd.cmd fix-bootcmd.scr
#
# POURQUOI. L'environnement U-Boot (memoire SPI) peut garder un ancien bootcmd (DTB Ultra, root=/dev/mmcblk0p2) : le noyau demarre, ne voit pas l'eMMC et
# attend « Waiting for root device ». Ce script le remplace par un bootcmd qui lit le boot.scr de l'eMMC (DTB v7-emmc, racine rootfs-emmc), puis, s'il echoue,
# le boot-usb.scr de la cle.
#
# UNE LIGNE, depuis la cle USB (console serie 115200 8N1, Entree au compte a rebours) :
#   usb start; load usb 0:1 ${loadaddr} fix-bootcmd.scr; source ${loadaddr}

echo "============================================"
echo "SecuBox ESPRESSObin v7 — fix bootcmd"
echo "============================================"
echo "bootcmd actuel : ${bootcmd}"

setenv bootcmd_avant "${bootcmd}"
setenv bootcmd 'mmc dev 1; if load mmc 1:1 ${loadaddr} boot.scr; then source ${loadaddr}; fi; usb start; if load usb 0:1 ${loadaddr} boot-usb.scr; then source ${loadaddr}; fi'
saveenv

echo "bootcmd fixe (eMMC puis USB). Ancien bootcmd garde dans bootcmd_avant."
echo "Revenir en arriere : setenv bootcmd \"\${bootcmd_avant}\"; saveenv"
echo "Redemarrer : reset"
