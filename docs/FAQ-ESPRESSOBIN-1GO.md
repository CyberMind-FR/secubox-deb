<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — ESPRESSObin v7 (951 Mo vus) : ce qui tient, ce qui sature, et le micrologiciel

> Guide pas à pas : [INSTALL-ESPRESSOBIN.md](INSTALL-ESPRESSOBIN.md).

Retour d'essai du 2026-10-16 sur une ESPRESSObin v7 (profil `minimal`, #2816, #2838, #2849).

## La carte ne répond plus (ping oui, SSH et HTTPS non)

Elle manque de mémoire vive : swap plein (950/950 Mo), `systemd-journald : Under memory pressure` dans `dmesg`, charge > 10. Pas de panne matérielle (aucune erreur d'E/S, aucun OOM-kill).
**Cause constatée** : installer de gros paquets (WAF `sbxwaf`, HAProxy) sur la carte vivante. Ils ont été retirés ; le WAF reste sur l'infrastructure (gk2).
**À faire** : installer en tâche détachée (`nohup … &`), jamais dans la session SSH (elle meurt avec le swap), puis attendre la charge < 5. Dernier recours : couper l'alimentation, puis `dpkg --configure -a`.

## `ndpid-engine` redémarre toutes les 5 s (« pcap_open_live: eth2 : No such device »)

`secubox-ndpid-engine` 1.7.1 lance nDPId sur `eth2` (valeur de gk2). Le choix de l'interface est dans **1.7.2** (#2740) ; `secubox-minimal` >= 0.5.1 l'exigeait (#2851).
Vérifier : `systemctl show secubox-ndpid-engine -p NRestarts`. Depuis `secubox-minimal` 0.10.0 (#3218), nDPId et le DPI ne sont plus dans le profil (en `Conflicts`).

## Alléger une carte déjà installée (#3218, banc gk5 du 2026-10-28)

Mesuré : swap de 819 à 489 Mo, PSS Python de 1012 à 646 Mo, une fois le DPI, les surplus (admin, profiles, routes, netdiag,
network-anomaly, ksm, premier-pas-console et huit minuteries), haproxy et le service portal arrêtés. DNS, blocage, pare-feu, maillage et
administration relayée par le maître restent corrects. Sur la carte, par la CLI (le profil coupe l'API du panneau /profiles/) :

1. `apt-get update && apt-get install secubox-minimal secubox-profiles` (en tâche détachée) : retire DPI, nDPId, Courbes et Routes, et
   met à jour `/etc/secubox/profiles/minimal.toml` s'il n'a pas été modifié (sinon la référence est posée en `minimal.toml.dpkg-dist`) ;
2. `secubox-profilectl diff --profile minimal` puis `secubox-profilectl apply --profile minimal --yes` ;
3. `systemctl disable --now haproxy` (préinstallé par les anciennes images, il n'écoute aucun port).

## L'agent Auto-Load a rejoué le nom et le mot de passe au redémarrage

Il reprend son étape « application » avec les réponses d'origine : le nom revient et le mot de passe d'usine peut être reposé (#2853). Contournement : `systemctl disable --now secubox-autoload-agent`.
Le mode réseau `routeur` échoue (« secubox-net-detect » n'est livré par aucune image) : utiliser `lan` (une seule carte, le réseau en place est conservé).

## Je ne peux plus me connecter en SSH

Le SSH de la carte est réservé au LAN (`192.168.1.0/24`) et au support depuis gk2 par le tunnel `wg-autoload` (`10.64.0.1`) : `/etc/secubox/hardening/nft-input-trust.d/00-ssh-lan.nft`.
Depuis gk2 : `ssh -i /etc/secubox/secrets/support-ssh/id_ed25519 -o IdentitiesOnly=yes root@10.64.0.9` (#2854 : à poser par l'enrôlement).

## Pourquoi pas le WAF sur la carte ?

HAProxy + sbxwaf + les unités absorbées (exposure, vhost) coûtent environ 100 Mo de plus sur une carte qui en a déjà 800 d'occupés. Les leurres de service et la détection de force brute
tournent sur gk2 (`sbx-authwatch`, dans `secubox-toolbox-ng`) ; l'administration de la carte y est publiée derrière le WAF (`admin.<nom>.secubox.in`, #2844).

## `secubox-portal` : pourquoi le garder ?

Il livre `login.html`, la page de connexion de la WebUI (le hub ne la livre plus depuis 1.9.6). Sans lui, plus de connexion par navigateur.
Son **service** est arrêté par le profil minimal (#3218, sans tête) : nginx sert la page, l'agrégateur sert `/api/v1/portal` et `/api/v1/auth`.

## La carte annonce 951 Mo : est-ce une 2 Go bridée ?

Vérifiez à la console (U-Boot, `bdinfo`) : sur la carte d'essai, `DRAM: 1 GiB` et une banque de 0x40000000, avec un micrologiciel `OpenWrt … (espressobin-v7-1gb)`.
La v7 existe en 1 Go et en 2 Go ; lisez l'étiquette ou les puces avant de conclure à un micrologiciel limité. Sur la carte d'essai, l'image OpenWrt `trusted-firmware-a-espressobin-v7-2gb` (21.02.7) a rendu la carte **muette** :
elle n'a pas la mémoire de cette configuration. Ne retentez pas le 2 Go sans preuve. Une v7 1 Go se reconnaît à `DRAM: 1 GiB` avec un micrologiciel `v7-1gb` qui démarre.

## La carte est muette après un flash de la SPI : récupération par l'UART, sans cavaliers

À faire AVANT tout flash : sauvegarder la SPI (`sf probe 0; sf read $loadaddr 0 0x400000; fatwrite usb 0:1 $loadaddr spi-sauvegarde.bin 0x400000`, 4 194 304 octets).
Récupération (testée le 2026-10-16) avec `mox-imager` (CZ.NIC, `gitlab.nic.cz/turris/mox-imager`, il faut `libncurses-dev` pour le compiler), l'image `flash-image.bin` d'une configuration qui démarre :
`./mox-imager -D /dev/ttyUSB0 -E --max-restarts=30 -t flash-image-1gb.bin`, puis couper et remettre l'alimentation (ou Reset) jusqu'à « Detected BootROM command prompt » ; compter 10 à 30 essais.
- **Pas de `-b 6000000`** : un adaptateur USB-série qui ne tient pas 6 Mbaud perd la liaison (« Timed out ») ; laisser 115200.
- `kwboot` ne convient pas (Armada 370/XP/38x seulement) ; l'outil Marvell `WtpDownload_linux` fonctionne, mais seulement par cavaliers (`J11 1-2, J3 1-2, J10 2-3`).
- Une fois U-Boot en mémoire : `usb start; bubt retour-1gb.bin spi usb`, puis `reset`.

L'image qui boote doit être la bonne pour la carte : un build qui ne s'initialise pas (mémoire, vitesses) donne `TIM-1.0 / WTMI … SVC REV` en boucle, sans `BL1`.
