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
  Tactile désactivable : remplacer la ligne par `dtoverlay=secubox-dsi-7inch,touch=off`.
- **ROOTPART** : raspi-firmware régénère `cmdline.txt` avec `root=/dev/mmcblk0p2` par défaut, alors
  que la SD est `mmcblk1` sous noyau Debian sur RPi4. Le postinst fixe `ROOTPART=UUID=<racine>`
  dans `/etc/default/raspi-firmware` s'il n'y est pas (jamais d'écrasement), et ne lance
  `update-initramfs` (vc4 DKMS dans l'initramfs) que si ROOTPART est défini.
- Hook `/etc/kernel/postinst.d/00-secubox-rpi-dsi` : à chaque nouveau noyau, avant dkms,
  initramfs-tools et raspi-firmware : ROOTPART puis overlay. Sur RPi4/400, s'il ne peut fixer
  ROOTPART, il fait échouer l'installation du noyau plutôt que d'écrire un `cmdline.txt` mortel.

Pas d'API, pas de socket, pas de service, pas d'utilisateur dédié. Décisions (ROOTPART, overlay)
journalisées dans `/var/log/secubox/audit.log`.

## Dépendances

`dkms`, `linux-source-6.12`, `linux-headers-arm64`, `patch`, `xz-utils`, `make`, `gcc`,
`raspi-firmware`, `initramfs-tools`, `util-linux`. Construction : `device-tree-compiler`.

## Installation

```sh
apt install secubox-rpi-dsi        # construit les modules, pose l'overlay, régénère l'initramfs
reboot
```

Image RPi : `sudo bash image/build-rpi-usb.sh --slipstream --rpi-dsi` (ou `INCLUDE_RPI_DSI=1`).
Le paquet reste inerte dans le chroot ; une fois sur la Pi : `dpkg-reconfigure secubox-rpi-dsi`.

Commande d'appoint : `secubox-rpi-dsi is-target|rootpart-ok|ensure-rootpart|install-overlay|remove-overlay|update-initramfs`.

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
