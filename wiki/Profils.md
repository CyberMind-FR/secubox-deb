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
| Mémoire visée | 2 Go | 4 à 8 Go | 8 Go et plus |
| Machine type | ESPRESSObin | Raspberry Pi 400, boîtes 4 Go | MOCHAbin |
| Analyse du trafic (DPI) | en miroir, léger | en miroir | en ligne |
| Conteneurs LXC | non | oui | oui |
| Swap | 512 Mo | aucun | aucun |

## Profils installables

Les profils s'emboîtent : **isp = lite + hébergement simple**, **full = isp + tout le parc**.

| | `secubox-lite` | `secubox-isp` | `secubox-full` |
|---|---|---|---|
| Rôle | Protections uniquement | Couche protégée, hébergement simple et limité | Totalité du parc actuel (comme la box de référence) |
| Protections | Pare-feu nftables, WAF (`sbxwaf`), DPI, MITM (`sbxmitm`), ad-guard, webfilter, menaces, anti-rootkit, contrôle d'accès, WireGuard | celles de lite | celles de lite |
| Réseau / FAI | DNS | + routage, QoS, certificats, exposition, Tor, maillage, supervision | idem isp |
| Hébergement | aucun | simple : metablogizer, publish | complet : Nextcloud, Gitea, Jellyfin, PeerTube, courrier, radio, BBS, billets, Zigbee… |

Un module absent du profil peut toujours s'installer à la main ; le profil fixe seulement la base d'une image neuve.

## Mémoire

Sur une machine de 2 Go, les listes de blocage DNS restent celles par défaut, petites, avec un seul profil de blocage. Un puits DNS de production de plus de 650 000 zones occupe environ 295 Mo, et chaque configuration de blocage distincte de webfilter ajoute environ 100 Mo : à réserver aux niveaux standard et pro.

Tableau complet, glossaire et prompt de vulgarisation : [`docs/PROFILS-COMPARATIF.md`](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/PROFILS-COMPARATIF.md).
