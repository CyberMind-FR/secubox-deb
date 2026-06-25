# SecuBox-Deb :: sbx-boot.cmd (#737, Phase 2)
# Exécuté par l'OVERLAY 2ᵉ U-Boot (chainloadé). Compilé en boot.scr :
#   mkimage -A arm64 -O linux -T script -C none -d sbx-boot.cmd sbx-boot.scr
# Doctrine : HTTP simple OK car le boot.fit servi est SIGNÉ (vérifié par bootm).
# Repli TFTP (fonctions usine garanties) si wget/HTTP indisponible.

setenv autoload no
echo "== SecuBox netboot overlay =="

# Réseau (DHCP fournit serverip + option next-server)
if dhcp; then
  setenv sbx_srv ${serverip}
else
  echo "DHCP KO -> arret overlay, retour amorce appelante"
  exit 1
fi

# Identifiant board pour le mapping image (MAC ; serial si dispo)
if test -z "${sbx_id}"; then setenv sbx_id ${ethaddr}; fi
echo "board=${sbx_id} server=${sbx_srv}"

# 1) Image assignée à CETTE board, en FIT signé, via HTTP
if wget ${loadaddr} http://${sbx_srv}/netboot/${sbx_id}/boot.fit; then
  echo "boot.fit recupere (HTTP) -> verification signature + boot"
  bootm ${loadaddr}
  echo "bootm a echoue (signature invalide ?) -> repli"
fi

# 2) Repli TFTP (kernel + dtb + initrd bruts) — fonctions usine garanties
echo "repli TFTP"
if tftpboot ${kernel_addr_r} ${sbx_srv}:netboot/${sbx_id}/Image; then
  tftpboot ${fdt_addr_r}    ${sbx_srv}:netboot/${sbx_id}/board.dtb
  if tftpboot ${ramdisk_addr_r} ${sbx_srv}:netboot/${sbx_id}/initrd.img; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r}
  else
    booti ${kernel_addr_r} - ${fdt_addr_r}
  fi
fi

echo "netboot overlay : aucune source -> retour amorce appelante"
exit 1
