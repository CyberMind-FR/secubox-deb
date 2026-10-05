<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Profils

Deux notions se croisent : le **niveau** (ce que la machine peut porter selon sa mémoire) et le **profil** (ce qu'on installe). Un profil est un méta-paquet : il ne contient rien lui-même, il tire d'autres paquets par ses dépendances.

## Niveaux

| | lite | standard | pro |
|---|---|---|---|
| Mémoire visée | 1 à 2 Go | 4 à 8 Go | 8 Go et plus |
| Machine type | ESPRESSObin | Raspberry Pi 400, boîtes 4 Go | MOCHAbin |
| Analyse du trafic (DPI) | non | en miroir | en ligne |
| Conteneurs LXC | non | oui | oui |
| Swap | 512 Mo | aucun | aucun |

## Profils installables

| | `secubox-lite` | `secubox-isp` | `secubox-full` |
|---|---|---|---|
| Rôle | Essentiel pour petite machine | Routeur / passerelle complète | ISP + applications |
| Contenu | Hub, portail, WireGuard, modes réseau, NAC, durcissement, ad-guard, webfilter | lite + DNS, pare-feu, WAF, HAProxy, QoS, DPI, certificats, exposition, Tor, maillage, supervision, hébergement de sites (metablogizer, publish) | isp + Nextcloud, Gitea, Jellyfin, PeerTube, Podcaster, torrent, courrier, Zigbee, radio, BBS, billets… |
| Niveau adapté | lite | standard | pro |

Un module absent du profil peut toujours s'installer à la main ; le profil fixe seulement la base d'une image neuve.

## Mémoire

Sur une machine de 1 à 2 Go, les listes de blocage DNS restent celles par défaut, petites. Un puits DNS de production de plus de 650 000 zones occupe environ 295 Mo, et chaque configuration de blocage distincte de webfilter ajoute environ 100 Mo : à réserver aux niveaux standard et pro.

Tableau complet, glossaire et prompt de vulgarisation : [`docs/PROFILS-COMPARATIF.md`](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/PROFILS-COMPARATIF.md).
