# SecuBox-Deb :: sbx-boot.cmd (#737, Phase 2)
# Exécuté par l'OVERLAY 2ᵉ U-Boot (chainloadé). Compilé en boot.scr :
#   mkimage -A arm64 -O linux -T script -C none -d sbx-boot.cmd sbx-boot.scr
# Source de boot = un host SecuBox "serveur" (ex: gk2) servant TFTP + HTTP.
# HTTP simple OK : le boot.fit est SIGNÉ (vérifié par bootm). Repli TFTP.
#
# Variables attendues (posées dans l'env du DUT par 'overlay apply', ou via DHCP):
#   sbx_srv  : IP/host du serveur de boot (sinon = serverip DHCP)
#   sbx_id   : identifiant board (defaut = ethaddr sans ':')

setenv autoload no
echo "== SecuBox netboot overlay =="

if dhcp; then : ; else echo "DHCP KO"; fi
if test -z "${sbx_srv}"; then setenv sbx_srv ${serverip}; fi
if test -z "${sbx_id}";  then setenv sbx_id ${ethaddr}; fi
if test -z "${sbx_port}"; then setenv sbx_port 8099; fi
echo "server=${sbx_srv} board=${sbx_id}"

# 1) HTTP : boot.fit SIGNÉ assigné à cette board
if wget ${loadaddr} http://${sbx_srv}:${sbx_port}/${sbx_id}/boot.fit; then
  echo "boot.fit (HTTP) recupere -> verif signature + boot"
  bootm ${loadaddr}
  echo "bootm KO (signature ?) -> repli TFTP"
fi

# 2) repli TFTP (racine serveur = /srv/secubox/netboot/tftp)
echo "repli TFTP"
if tftpboot ${kernel_addr_r} ${sbx_srv}:${sbx_id}/Image; then
  tftpboot ${fdt_addr_r} ${sbx_srv}:${sbx_id}/board.dtb
  if tftpboot ${ramdisk_addr_r} ${sbx_srv}:${sbx_id}/initrd.img; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r}
  else
    booti ${kernel_addr_r} - ${fdt_addr_r}
  fi
fi

echo "netboot overlay : aucune source -> retour amorce appelante"
exit 1
