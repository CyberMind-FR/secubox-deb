<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Roadmap

État courant du projet et suite prévue. Cette roadmap est **non datée** — le projet progresse au rythme des moyens disponibles.

---

## État courant

### Version

| Élément | Valeur |
|---------|--------|
| Version release | v3.0.0-alpha.8 (pré-release) |
| Base Debian | bookworm (12) ; images Trixie (13) pour VM et Raspberry Pi |
| Paquets | environ 190 |
| Profils | `lite`, `isp`, `full` |

### Ce qui est livré et en service

| Domaine | Modules et développements |
|---------|---------------------------|
| 🛡️ Pare-feu et WAF | nftables en `DEFAULT DROP`, `sbxwaf` (WAF en Go) devant tout le trafic web, HAProxy TLS 1.3 en frontal, bannissement natif nftables, empreintes d'outils et campagnes de scanners |
| 🧹 DNS | Unbound ; **ad-guard** (publicités et traceurs, par appareil, TV et streamers) ; **webfilter** (catégories adulte, jeux d'argent, phishing/malware, profils et appareils, observation par défaut) ; `dns-lan` (noms du réseau local) ; DNS Guard |
| 🔐 Accès | WireGuard avec enrôlement par QR, authentification avec 2FA administrateur, NAC |
| 🕵️ Détection | DPI (nDPI 6.x), sentinelle, apprentissage C2, anti-rootkit, CrowdSec en mode souverain |
| 🧅 Réseau privé | Tor (passerelle transparente `.onion`), maillage `wg-mesh`, annuaire Gondwana à trois nœuds, fédération P2P |
| 🧰 Toolbox | Niveaux d'interception par appareil (off, passif, actif, réel) avec le moteur Go `sbxmitm` |
| ☁️ Services souverains | Nextcloud, messagerie (Maildir, Sieve, ClamAV), Gitea, Jellyfin, PeerTube, Podcaster, radio, BBS, billets, publication de sites (metablogizer), Zigbee, Meshtastic, YouTube SAS — chacun dans son conteneur LXC |
| 🖥️ Interface | Tableau de bord unique, Hall (bureau web), panneaux d'administration par module |
| ⚙️ Exploitation | Profils avec niveaux de mémoire, `sleeper` et réveil à la demande, zram, plafond collectif de mémoire, watchdog avec auto-réparation des conteneurs, anneaux de publication (release rings) |

### Matériel

| Carte | SoC | Statut | Profil conseillé |
|-------|-----|--------|------------------|
| MOCHAbin | Armada 7040 | ✅ Testé et supporté | `full` |
| ESPRESSObin v7 / Ultra | Armada 3720 | ✅ Testé et supporté | `lite` (isp possible) |
| Raspberry Pi 4 / 400 | BCM2711 | ✅ Testé et supporté | `isp` |
| PC x86_64, VirtualBox, QEMU | — | ✅ Testé et supporté | `isp` ou `full` |
| ClearFog Base/Pro | Armada 388 | 🔵 Porté par la communauté | `lite` |

### Infrastructure

| Service | Statut |
|---------|--------|
| Dépôt APT `apt.secubox.in` | ✅ Opérationnel |
| CI/CD GitHub Actions | ✅ Paquets, images, Live USB, ISO d'installation |
| Wiki multilingue | ✅ EN/FR/DE/ZH (pages principales) |

---

## En cours et à venir

| Sujet | Contenu |
|-------|---------|
| Webfilter, suite | Apprentissage et mise en quarantaine (« parking »), association avec le DPI |
| DPI | Étiquetage des destinations vues par IP seule |
| Toolbox | Export des compteurs vers ad-guard |
| Portage Trixie | Image CI puis ensemble des paquets |
| Certification CSPN | Documentation article par article, politique cryptographique, audit externe |
| Secrets matériels (TPM) | Étudié, mis de côté : gain limité tant que la clé d'hôte reste sur le même disque |

Idées étudiées puis suspendues, sans calendrier : enregistreur de replay TV local (suspendu : contenus sous DRM hors périmètre).

---

## Wishlist — Hardware

Cibles matérielles en attente de portage ou de sponsor.

| Carte | SoC | Budget estimé | Intérêt |
|-------|-----|---------------|---------|
| **MACCHIATObin** | Armada 8040 | ~12 000 € | Server-grade 10GbE |
| **HoneyComb LX2K** | LX2160A | ~15 000 € | 25GbE, NVMe |
| **Banana Pi BPI-R4** | MT7988A | ~6 000 € | MediaTek 2.5GbE |
| **NanoPi R6S** | RK3588S | ~5 000 € | Rockchip compact |
| **Traverse Ten64** | LS1088A | ~10 000 € | Open hardware |
| **Raspberry Pi 5** | BCM2712 | ~3 000 € | RPi nouvelle génération |

Voir **[[Sponsor-a-Port]]** pour financer un portage.

---

## Wishlist — Certification

| Objectif | Horizon | Notes |
|----------|---------|-------|
| Tests unitaires ≥ 80% | En cours | Couverture pytest progressive |
| Documentation CSPN | En cours | Conformité article par article |
| Audit externe | Après financement | Nécessite budget dédié |
| Soumission ANSSI | 2027 | Objectif non contractuel |

---

## Contribuer

Les contributions sont bienvenues sur tous les éléments de la wishlist.

- **Code** : PR sur GitHub, voir `CONTRIBUTING.md`
- **Documentation** : Traductions, corrections, tutoriels
- **Tests** : Rapports de bugs, tests sur matériel exotique
- **Financement** : Voir [[Support]] et [[Sponsor-a-Port]]

---

## Ce que cette roadmap ne contient pas

- **Dates prévisionnelles** — Le projet avance au rythme des moyens disponibles
- **Promesses de livraison** — Les items wishlist sont des intentions, pas des engagements
- **Stretch goals** — Pas de mécanique "si on atteint X, on fera Y"

---

*Dernière mise à jour : 2026-10*
