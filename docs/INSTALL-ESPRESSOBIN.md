<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔴 Installer SecuBox sur une ESPRESSObin

De la carte nue à une box rattachée à gk2, en neuf étapes. Chaque étape dit quoi taper, ce qu'on doit voir, et quoi faire si ça ne vient pas.

Testé sur une ESPRESSObin v7 de 1 Go (951 Mo utilisables), du 16 au 18 octobre 2026. Les points marqués **non vérifié** ou **à définir** ne sont pas encore confirmés. Voir aussi [FAQ-ESPRESSOBIN-1GO.md](FAQ-ESPRESSOBIN-1GO.md) (micrologiciel, récupération UART) et [AUTOLOAD-ATELIER.md](AUTOLOAD-ATELIER.md) (préparation automatique d'une carte).

## 1. Matériel

| Élément | Détail |
|---|---|
| Carte | ESPRESSObin v7, alimentation 12 V |
| Clé USB | 8 Go ou plus, sur la prise USB 3.0 de la carte (clé d'essai : Kingston DataTraveler 3.0) |
| Console série | adaptateur USB-série 3,3 V sur la prise micro-USB de la carte, 115 200 bauds 8N1, sans cavaliers |
| Réseau | câble Ethernet sur le port WAN (eth0), DHCP du réseau local |
| Poste | un terminal série (`minicom`) ; sur disque : `mox-imager`, `flash-image-1gb.bin` |

> ⚠️ La v7 existe en 1 Go et en 2 Go. Lisez l'étiquette ou les puces mémoire avant de choisir une image.

## 2. Télécharger l'image et préparer la clé

Le plus simple : la dernière release publiée sur GitHub.

```bash
TAG=$(gh release list -R CyberMind-FR/secubox-deb -L 1 --json tagName -q '.[0].tagName')
gh release download "$TAG" -R CyberMind-FR/secubox-deb -p 'secubox-lite-espressobin-v7-trixie.img.xz'
```

Repérer la clé, puis écrire l'image dessus. Remplacer `sdX` par le nom de la clé, **jamais** par celui d'un disque du poste :

```bash
lsblk -o NAME,SIZE,MODEL,TRAN
xz -dc secubox-lite-espressobin-v7-trixie.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

On doit voir un fichier `.img.xz` d'environ 1,8 Go, puis `dd` qui écrit quelques Go sans erreur.

> **Non vérifié.** La release v3.0.0-alpha.18 publie une image *lite* pour l'ESPRESSObin v7, pas une clé « live installer » dédiée. Qu'elle démarre depuis la clé avec `boot-usb.scr` et propose `secubox-install-emmc` reste à confirmer sur la carte. Aucune somme de contrôle `.sha256` n'accompagne cette image.

**Alternative avancée : construire l'image soi-même** (version précise, paquets locaux). Droits root, plusieurs Go de disque et du temps : la construction installe un système Debian complet.

```bash
sudo bash image/build-ebin-live-usb.sh --suite trixie --size 2G
```

Elle produit `output/secubox-espressobin-v7-live-usb.img` (et `.img.gz`), à écrire avec `dd` comme ci-dessus.

**Contrôler la clé.** Sur la clé d'essai, `boot-usb.scr`, `Image` et `initrd.img` sont à la racine de la première partition. Si `boot-usb.scr` manque, l'étape 5 ne démarrera pas.

**Pour pouvoir récupérer une carte**, copier aussi sur la clé la sauvegarde de la SPI (étape 4) et l'image de retour `retour-1gb.bin`, comme sur la clé d'essai.

> 🔴 `dd` efface la cible sans demander. Vérifier le nom du périphérique avec `lsblk` : taille et modèle doivent être ceux de la clé.

## 3. Ouvrir la console série

```bash
minicom -D /dev/ttyUSB0 -b 115200
```

Rien ne s'affiche tant que la carte n'est pas alimentée. À la mise sous tension : `TIM-1.0`, `WTMI`, puis `Hit any key to stop autoboot`.

Si minicom affiche « Déconnecté », c'est la liaison série qui est tombée, pas la carte : rebrancher l'adaptateur.

## 4. Lire la mémoire et sauvegarder la SPI

Appuyer sur une touche pendant le compte à rebours pour arrêter le démarrage, puis, à U-Boot :

```
bdinfo
usb start
sf probe 0
sf read $loadaddr 0 0x400000
fatwrite usb 0:1 $loadaddr spi-sauvegarde.bin 0x400000
```

On doit voir `DRAM: 1 GiB` (ou 2 GiB), puis un fichier `spi-sauvegarde.bin` de 4 194 304 octets sur la clé : c'est le retour en arrière.

> 🔴 Une image 2 Go flashée sur une carte 1 Go la rend muette : la console s'arrête après `Running on ESPRESSObin`. Ne flasher le micrologiciel que si l'image correspond à la mémoire lue ici.

## 5. Démarrer depuis la clé

```
usb start
load usb 0:1 ${loadaddr} boot-usb.scr
source ${loadaddr}
```

On doit voir `Kernel loaded OK`, `Initramfs loaded`, `Booting SecuBox from USB...`, puis le noyau Debian 6.12 et l'invite de connexion.

- « Failed to load boot/boot.scr » : le script s'appelle `boot-usb.scr` et se trouve à la racine de la clé. Lister la clé avec `ls usb 0:1`.
- « Failed to load … .img.gz » est normal : la clé ne porte pas d'image à copier.

## 6. Se connecter et contrôler le système

Se connecter avec `root` et le mot de passe de l'image, à changer dès l'installation terminée.

```bash
secubox-status
```

On doit voir une mémoire autour de 951 Mo, une adresse sur `eth0` et les services de base démarrés.

## 7. Installer sur l'eMMC

```bash
secubox-install-emmc
```

On doit voir la source `/dev/sda`, la cible `/dev/mmcblk0`, le plan (boot 512 Mo, système, données 512 Mo), puis la demande de confirmation : taper `mmcblk0`. La copie dure quelques minutes.

> 🔴 Tout le contenu de l'eMMC est effacé. Ne pas couper l'alimentation pendant « copie du système » : une copie interrompue laisse un eMMC à moitié écrit.

## 8. Redémarrer sur l'eMMC et alléger

Retirer la clé, redémarrer, se reconnecter. Sur 1 Go, ne pas garder le WAF ni HAProxy : ils saturent la carte (swap plein, charge au-delà de 10). Installer le profil minimal et changer le mot de passe :

```bash
passwd
apt-get update
apt-get install secubox-minimal
```

> **Non testé comme procédure** : l'installation de `secubox-minimal` après le premier démarrage est une recommandation. Si la carte retombe sur U-Boot sans démarrer, le démarrage eMMC n'est pas réglé dans l'environnement U-Boot : noter ce qui s'affiche, la commande dépend de la version.

## 9. Rejoindre gk2 par WireGuard

La carte devient pair p2p de gk2 (le maître) par le tunnel d'infrastructure. Cette étape est aujourd'hui manuelle ; son automatisation à la première préparation est prévue (voir `.claude/TODO.md`).

On doit voir, sur gk2, la carte listée « approved » avec une adresse mesh (10.10.0.x), et un ping qui répond vers 10.10.0.1 depuis la carte.

**À définir :** où vit le jeton d'invitation (jamais en clair dans l'image) et sa durée de validité.

## Si la carte reste muette après un flash : récupération par l'UART

Aucun cavalier. Sur le poste, console série fermée :

```bash
./mox-imager -D /dev/ttyUSB0 -E --max-restarts=30 -t flash-image-1gb.bin
```

Couper puis remettre l'alimentation jusqu'à « Detected BootROM command prompt » (10 à 30 essais). Garder 115 200 bauds : un adaptateur qui ne tient pas 6 Mbauds perd la liaison. Une fois U-Boot en mémoire :

```
usb start
bubt retour-1gb.bin spi usb
reset
```
