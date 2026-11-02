<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-rpi-dsi — écran officiel Raspberry Pi 7" (DSI) sur noyau Debian

Paquet **optionnel** (#3399), réservé à un Raspberry Pi 4 / 400 équipé de l'écran officiel 7"
(nappe DSI, 800x480, tactile FT5406). Aucun méta-paquet ni profil d'image ne le tire ; ailleurs
que sur un RPi4/400, son postinst ne fait rien et le dit.

## Ce qu'il fait

- **DKMS** (`secubox-rpi-dsi`, `AUTOINSTALL`) : pour chaque noyau, extrait de
  `/usr/src/linux-source-<maj.min>.tar.xz` les sources de `vc4`, `tc358762`, `panel-simple` et
  `edt-ft5x06`, applique les 5 patches de `patches/` (sans fuzz, à blanc d'abord : tout ou rien),
  construit les 4 modules dans `updates/dkms`. La version de `linux-source` doit être celle du
  noyau, sinon refus. Un échec = aucun module installé.
- **Overlay** `secubox-dsi-7inch.dtbo` (compilé au build, `/usr/lib/secubox-rpi-dsi/`) copié dans
  `/boot/firmware/overlays/` ; `dtoverlay=secubox-dsi-7inch` ajouté à
  `/etc/default/raspi-firmware-custom` (lu par raspi-firmware). `config.txt` n'est jamais édité.
  Tactile désactivable : remplacer la ligne par `dtoverlay=secubox-dsi-7inch,touch=off`
  (paramètre `touch = <0>,"=4"` : active/désactive le fragment 4).
- **Montée de version** : une seule version DKMS enregistrée (les autres sont retirées avant `dkms add`).
- **Ordre linux-source / linux-image** : trigger dpkg `interest-noawait` sur
  `/usr/src/linux-source-6.12.tar.xz` (relance la construction + initramfs) et unité oneshot
  `secubox-rpi-dsi-boot.service` (activée, jamais lancée par le postinst) qui, au démarrage,
  reconfigure si les 4 modules manquent pour le noyau courant. La révision Debian de
  `linux-source` est comparée à celle de `linux-image-<noyau>` quand elle est connue.
- **ROOTPART** : raspi-firmware régénère `cmdline.txt` avec `root=/dev/mmcblk0p2` par défaut, alors
  que la SD est `mmcblk1` sous noyau Debian sur RPi4. Le postinst fixe `ROOTPART=UUID=<racine>`
  dans `/etc/default/raspi-firmware` s'il manque ou n'est pas sûr, et ne lance
  `update-initramfs` (vc4 DKMS dans l'initramfs) que si ROOTPART est sûr. Sûr = `UUID=…`,
  `PARTUUID=…` ou un chemin existant, jamais `/dev/mmcblk0p*` sur RPi4/400 ; une valeur sûre
  n'est jamais écrasée, une valeur non sûre est mise en commentaire (`# secubox-rpi-dsi (non sûr)`).
- Hook `/etc/initramfs/post-update.d/00-secubox-rpi-dsi` : revérifie ROOTPART à chaque
  `update-initramfs`, avant `z50-raspi-firmware`.
- Hook `/etc/kernel/postinst.d/00-secubox-rpi-dsi` : à chaque nouveau noyau, avant dkms,
  initramfs-tools et raspi-firmware : ROOTPART puis overlay. Sur RPi4/400, s'il ne peut fixer
  ROOTPART, il fait échouer l'installation du noyau plutôt que d'écrire un `cmdline.txt` mortel.

Pas d'API, pas de socket, pas d'utilisateur dédié ; une seule unité oneshot root (exception § 10
inscrite dans `.claude/RULES-CODE.md`). Décisions (ROOTPART, overlay)
journalisées dans `/var/log/secubox/audit.log` (ouvert sans suivre de lien), ainsi que
`dkms install/remove` et `update-initramfs`.

### Piège du conffile

`/etc/default/raspi-firmware` est un conffile de `raspi-firmware`. Après notre ajout de ROOTPART,
une mise à jour de raspi-firmware qui modifie ce fichier pose la question dpkg habituelle :
**garder la version installée** (choix par défaut, `--force-confold`). Si la version du mainteneur
est prise, ROOTPART disparaît : le hook `post-update.d` le remet avant `z50-raspi-firmware`, mais
vérifier `grep ROOTPART /etc/default/raspi-firmware` après coup.

### Déblocage (hook noyau ou initramfs en échec)

Sur RPi4/400, si ROOTPART ne peut être rendu sûr (racine sans UUID), les hooks sortent en 1 et
l'installation du noyau reste « à configurer » : c'est voulu, `cmdline.txt` n'est pas réécrit.

```sh
findmnt -n -o UUID,PARTUUID /                       # repérer l'identifiant de la racine
echo 'ROOTPART=PARTUUID=<partuuid>' | sudo tee -a /etc/default/raspi-firmware
sudo secubox-rpi-dsi rootpart-ok && sudo dpkg --configure -a
```

## Dépendances

`dkms`, `linux-source-6.12`, `linux-headers-arm64`, `patch`, `xz-utils`, `make`, `gcc`,
`raspi-firmware`, `initramfs-tools`, `util-linux`. Construction : `device-tree-compiler`.

## Installation

```sh
apt install secubox-rpi-dsi        # construit les modules, pose l'overlay, régénère l'initramfs
reboot
```

Image RPi : `sudo bash image/build-rpi-usb.sh --slipstream --rpi-dsi` (ou `INCLUDE_RPI_DSI=1`).
Le paquet reste inerte dans le chroot ; `secubox-rpi-dsi-boot.service` construit les modules et
pose l'overlay au premier démarrage (puis redémarrer pour l'écran).

Commande d'appoint : `secubox-rpi-dsi is-target|rootpart-ok|ensure-rootpart|install-overlay|remove-overlay|dkms-sync|dkms-remove|update-initramfs|configure|boot-check`.

Extraction : `tar` (outil, pas `tarfile`) avec une liste de membres fixes, `--no-same-owner`,
`--no-same-permissions`, dans une destination confinée au répertoire DKMS ; l'archive est celle du
paquet Debian `linux-source`. RULES-CODE § 1 vise les extractions Python d'archives non fiables :
pas d'exception à inscrire.

## Retrait

```sh
apt purge secubox-rpi-dsi
reboot
```

Le `prerm` retire les modules DKMS (tous noyaux), l'overlay copié et la ligne
`dtoverlay=secubox-dsi-7inch` de `raspi-firmware-custom`, puis régénère l'initramfs (vc4 d'origine).
`ROOTPART` est **laissé en place** dans `/etc/default/raspi-firmware` : le retirer rendrait la box
non démarrable à la prochaine régénération de `cmdline.txt`.

## Tests

`pytest packages/secubox-rpi-dsi/tests` : application des patches sur Linux v6.12.107 (téléchargé
depuis git.kernel.org, sinon skip), refus de version, patch refusé sans reste, logique ROOTPART,
overlay idempotent, compilation `dtc`, conformité debian/.

## Licence

Nos fichiers : CMSD-1.0. `patches/*.patch` et les modules produits : GPL-2.0 (voir
`debian/copyright`).
