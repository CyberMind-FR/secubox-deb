<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Raspberry Pi 4 — écran officiel 7" (DSI) et tactile

> Une box SecuBox sur **Raspberry Pi 4 / 400** peut afficher son interface (assistant « premier pas », Hall,
> administration) sur l'**écran officiel Raspberry Pi 7"** branché en nappe, et se configurer **au doigt**,
> sans clavier ni autre ordinateur. Le paquet optionnel `secubox-rpi-dsi` le rend possible sur le noyau Debian.

Validé le 2 novembre 2026 sur un Raspberry Pi 4 Model B **4 Go** (box de banc gk7) : écran 800x480, tactile,
kiosque, premier pas et Hall, au démarrage et sans intervention.

---

## Matériel

| Élément | Détail |
|---|---|
| Carte | Raspberry Pi 4 Model B ou Raspberry Pi 400. 4 Go suffisent ; pour une nouvelle box, **préférer un Raspberry Pi 5 8 Go** (voir [[Hardware-Matrix]]). |
| Écran | Écran tactile officiel Raspberry Pi 7" (800x480, tactile FT5406). |
| Branchement | **Nappe DSI** sur le connecteur « DISPLAY » de la carte, et alimentation 5 V / masse (fils rouge et noir) sur le GPIO. |
| Fils SDA/SCL (vert, jaune) | Inutiles : l'écran et le tactile passent par la nappe. On peut les laisser ou les retirer. |

## Installer

Le paquet n'est **jamais** installé d'office. Sur la box :

```
apt install secubox-rpi-dsi
```

L'installation télécharge les sources du noyau, construit les pilotes (plusieurs minutes) et prépare le
démarrage. **Redémarrez ensuite** : l'écran et le tactile fonctionnent dès le démarrage suivant.

Pour une image prête à flasher, `image/build-rpi-usb.sh --rpi-dsi` inclut le paquet ; la box se configure
seule à son premier démarrage.

## Ce que fait le paquet

- **Pilotes** : le noyau Debian n'a pas tout ce qu'il faut pour cet écran. Le paquet reconstruit, pour le noyau
  installé et à chaque nouveau noyau (DKMS), quatre pilotes corrigés repris du noyau Raspberry Pi : affichage
  (`vc4`), pont DSI (`tc358762`), dalle (`panel-simple`) et tactile (`edt-ft5x06`, interrogation sans
  interruption). Si un correctif ne s'applique plus, rien n'est installé et la box démarre comme avant, sans écran.
- **Description de l'écran** (overlay `secubox-dsi-7inch`) : déclarée par
  `/etc/default/raspi-firmware-custom`, jamais en éditant `config.txt` à la main. Le tactile peut être coupé :
  `dtoverlay=secubox-dsi-7inch,touch=off`.
- **Garde-fou au démarrage** : le paquet fixe `ROOTPART=UUID=…` dans `/etc/default/raspi-firmware`.

## Piège connu : box qui ne démarre plus après une mise à jour du noyau

Sur Raspberry Pi avec le noyau Debian, le paquet `raspi-firmware` régénère `config.txt` **et** `cmdline.txt` à
chaque mise à jour du noyau ou de l'initramfs. Sans `ROOTPART`, il écrit `root=/dev/mmcblk0p2`, alors que la
carte SD s'appelle `mmcblk1` : la box affiche le texte de démarrage puis s'arrête, sans journal.

`secubox-rpi-dsi` fixe `ROOTPART` et refuse toute régénération tant qu'il n'est pas sûr. Si une box est déjà
dans cet état :

1. Retirer la carte SD et l'ouvrir sur un autre ordinateur.
2. Dans la partition de démarrage, éditer `cmdline.txt` : remplacer `root=/dev/mmcblk0p2` par
   `root=UUID=<UUID de la partition système>` (donné par `lsblk -no UUID` sur la partition ext4).
3. Remettre la carte et redémarrer, puis vérifier `ROOTPART` dans `/etc/default/raspi-firmware`.

## Retirer

```
apt purge secubox-rpi-dsi
```

Les pilotes, l'overlay et la ligne de `raspi-firmware-custom` sont retirés ; `ROOTPART` reste en place pour que
la box continue de démarrer.

---

Détails techniques : `packages/secubox-rpi-dsi/README.md` · suivi : issue #3399.
