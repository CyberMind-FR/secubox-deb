# Topologie de test — 2 MOCHAbin (#737)

```
   gk2 (MOCHAbin actuel) = SERVEUR de boot, UNTOUCHED (B0)
   ┌───────────────────────────────────────────────┐
   │ tftpd-hpa  -> /srv/secubox/netboot/tftp/<id>/  │
   │ nginx vhost boot.gk2.secubox.in (HTTP simple)  │
   │            -> /srv/secubox/netboot/http/<id>/  │
   │ API+UI /netboot/ : profils, publish, status    │
   │  (AUCUN overlay/flash sur gk2 — il ne fait que servir) │
   └───────────────────────────┬───────────────────┘
                LAN 192.168.1.0/24 │  HTTP(boot.fit signé) + TFTP(repli)
                                   ▼
   DUT (2e MOCHAbin) = device under test
   factory U-Boot → overlay 2e U-Boot (chainload) → sbx-boot.scr
        → wget boot.fit (B2) | tftp Image (B1) → booti
        → (B3) installeur DL image signée → écrit eMMC → reboot
```

## Pré-requis
- gk2 et le DUT sur le **même LAN** (192.168.1.0/24).
- DNS LAN `boot.gk2.secubox.in → 192.168.1.200` **ou** utiliser l'IP directe
  (le profil DUT met `srv: "192.168.1.200"`, pas de DNS requis).
- Console série UART (115200) sur le DUT pour le 1er passage (calibration + preuve).

## A. Côté SERVEUR (gk2) — non-invasif, reste B0
```bash
# 1) installer le paquet (n'active aucun overlay/flash local)
dpkg -i secubox-netboot_*.deb
# 2) activer le rôle serveur (racines + tftpd-hpa + vérif nginx /sbxboot)
secubox-netboot-serve up
secubox-netboot-serve status        # tftpd actif, nginx_sbxboot=yes
# 3) profil gk2 = B0 (sécurité), profil DUT = B2 (ou B1 pour chain-proof)
#    via l'UI /netboot/ (Profils) ou /api/v1/netboot/profiles
```

## B. Préparer les artefacts (par image)
```bash
# overlay 2e U-Boot pour mochabin (FIT signé) — clé DEV auto-générée la 1re fois
scripts/build-uboot-overlay.sh --board mochabin --uboot-bin <u-boot.bin> \
    --key-dir /etc/secubox/netboot/keys --out /var/lib/secubox/netboot/staging/overlay
# boot.fit signé (B2) dans le staging de l'image
secubox-netboot-publish --id <MAC_DUT> --sign \
    --kernel /boot/Image-mpcie-fix --dtb /boot/armada-7040-mochabin-mpcie-fix.dtb \
    --initrd <installer-or-rescue.initrd> --addrs board/mochabin/addrs.env
```

## C. Côté DUT (2e MOCHAbin) — banc série
1. **Relever l'env usine** (1 fois) : `version`, `printenv bootcmd`, `printenv loadaddr fdt_addr_r kernel_addr_r ramdisk_addr_r`, `mtd list` → caler `fw_env.config` + `board/mochabin/addrs.env`.
2. Déposer l'overlay en shadow (`/boot/secubox-netboot/shadow/sbx-uboot.fit` + `sbx-boot.scr`).
3. `secubox-netboot-overlay apply --commit` (sauve `factory_bootcmd`, pose le détournement + `bootcount`/`altbootcmd`).
4. **Reboot** → l'usine chaîne l'overlay → `sbx-boot.scr` → wget `boot.fit` (B2) → `bootm` vérifie la signature → boot.

## D. Preuves attendues (DoD)
- **B1 (chain-proof)** : le DUT boote le kernel servi par gk2 via TFTP.
- **B2 (signé)** : un `boot.fit` **valide** boote ; un `boot.fit` **mal signé** est
  REFUSÉ par `bootm` → repli/halte (pas de boot non vérifié).
- **Anti-brick** : overlay KO ×3 → `altbootcmd` → **retour usine automatique**,
  le DUT reboote sur son OS local sans intervention.
- **gk2 untouched** : `secubox-netboot-overlay status` sur gk2 montre
  `overlay_active=no`, `has_factory_backup=no` (jamais modifié).

## E. Rollback DUT
`secubox-netboot-overlay revert --commit` (restaure `factory_bootcmd`, retire le FIT).
