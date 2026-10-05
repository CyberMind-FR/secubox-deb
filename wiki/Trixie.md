<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Debian 13 (Trixie)

**Debian 13 (Trixie) est la base de SecuBox à partir de l'alpha 9.** Les paquets sont construits en `~trixie1` et publiés dans la suite `trixie` de `apt.secubox.in`. La suite `bookworm` n'évolue plus.

## Ce qui change

| | bookworm (12) | trixie (13) |
|---|---|---|
| Noyau | 6.6 LTS | 6.12 |
| Python | 3.11 | 3.13 |
| nginx | 1.22 | 1.26 |
| HAProxy | 2.6 | 3.0 |
| Unbound | 1.17 | 1.26 |
| LXC | 5.0 | 6.0 |

## Mise à jour en place (testée sur deux machines)

La mise à jour d'une box Debian 12 vers Debian 13 a été faite et validée sur un PC amd64 et sur une MOCHAbin (environ 10 et 45 minutes, sans retrait de paquet SecuBox). Déroulé :

1. Sauvegarder l'état de référence (services actifs, ports en écoute, conteneurs, `/etc/apt`).
2. Pointer les sources apt vers `trixie`, `trixie-updates` et `trixie-security`.
3. Bloquer par une préférence apt les paquets non voulus : `exim4*` (le courrier est dans un conteneur) et, sur la MOCHAbin, les noyaux Debian.
4. Simuler (`apt-get -s full-upgrade`), puis `apt upgrade --without-new-pkgs` et `apt full-upgrade`, dans une unité systemd détachée, avec le cache apt sur un volume de données si la racine est petite.
5. Installer `python3-python-multipart`, recréer les environnements virtuels Python restants, redémarrer, puis comparer à l'état de référence.

## Pièges rencontrés

| Symptôme | Cause | Remède |
|---|---|---|
| Plusieurs modules en boucle de redémarrage | `python-multipart` installé par pip pour Python 3.11 | `python3-python-multipart` (et non `python3-multipart`, une autre bibliothèque) |
| Un module à environnement virtuel ne démarre plus | Venv construit pour Python 3.11 | Recréer le venv (le paquet billets le fait maintenant tout seul) |
| `nftables` échoue, le maillage aussi | Les interfaces deviennent `end0` et `end1` | `net.ifnames=0` sur la ligne de commande du noyau |
| 421 sur tous les sites publics en navigateur | HAProxy 3.0 négocie HTTP/2 ; la réécriture d'URI utilisait `%[url]` | `%[pathq]` (corrigé dans `secubox-haproxy` 1.8.26) |
| `systemctl is-active` échoue pendant la mise à jour | `systemd` se met à jour lui-même | Suivre un message de fin dans le journal, pas l'état de l'unité |
| Le surfer renvoie 502 sur un `.onion` | Il forçait https | http pour les `.onion` (corrigé dans `secubox-surf` 1.0.30) |

## MOCHAbin : noyau

Le noyau Debian standard ne détecte pas le port WAN (eth2) de la MOCHAbin ; la carte reste sur son noyau 6.12 construit par SecuBox (fragments de configuration dans `board/mochabin/kernel/`). La carte démarre par `extlinux`, pas par `boot.scr`.

## Suite

Les conteneurs applicatifs restent en bookworm et passent à Trixie un par un.
Suivi : [#1294](https://github.com/CyberMind-FR/secubox-deb/issues/1294) et [#1997](https://github.com/CyberMind-FR/secubox-deb/issues/1997).
