<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Roadmap

État courant du projet et wishlist de développement. Cette roadmap est **non datée** — le projet progresse au rythme des moyens disponibles.

---

## État courant

### Version

| Élément | Valeur |
|---------|--------|
| Version release | v2.2.4-pre1 |
| Base Debian | bookworm (12) |
| Kernel | 6.6 LTS |
| Paquets | 125 |
| Endpoints API | 2000+ |

### Modules complets

Les modules suivants sont fonctionnels et testés :

| Stack | Modules |
|-------|---------|
| 🟠 AUTH | auth, portal, users, nac |
| 🟡 WALL | waf, authwatch, threats, ipblock, mitmproxy |
| 🔴 BOOT | cloner, vault, vm, rezapp |
| 🟣 MIND | dpi, netifyd, ai-insights |
| 🟢 ROOT | core, hub, system, console |
| 🔵 MESH | wireguard, haproxy, netmodes, qos |

### Ports livrés

| Carte | SoC | Statut | Profile |
|-------|-----|--------|---------|
| MOCHAbin | Armada 7040 | ✅ Tested & Supported | Full |
| ESPRESSObin v7 | Armada 3720 | ✅ Tested & Supported | Lite |
| ESPRESSObin Ultra | Armada 3720 | ✅ Tested & Supported | Lite+ |
| VirtualBox x64 | — | ✅ Tested & Supported | Full |
| QEMU ARM64 | — | ✅ Tested & Supported | Full |
| ClearFog Base/Pro | Armada 388 | 🔵 Community Ported | Lite |

### Infrastructure

| Service | Statut |
|---------|--------|
| APT repo `apt.secubox.in` | ✅ Opérationnel |
| CI/CD GitHub Actions | ✅ Cross-compilation ARM64 |
| Wiki multilingue | ✅ EN/FR/DE/ZH |
| Images bootables | ✅ ARM64 + AMD64 |

---

## Wishlist — Modules

Développements envisagés, sans engagement de date.

### Priorité haute

| Module | Description | Complexité |
|--------|-------------|------------|
| **secubox-soc** | SIEM/SOC interface, alerting consolidé | Moyenne |
| **secubox-backup** | Sauvegarde chiffrée, restore automatisé | Moyenne |
| **secubox-vpn-client** | Client VPN multi-protocole (WG/OpenVPN/IPsec) | Faible |

### Priorité moyenne

| Module | Description | Complexité |
|--------|-------------|------------|
| **secubox-honeypot** | Honeypots légers intégrés | Moyenne |
| **secubox-compliance** | Rapports conformité (RGPD, ISO 27001) | Haute |
| **secubox-meshnet** | MirrorNet P2P production | Haute |

### Priorité basse

| Module | Description | Complexité |
|--------|-------------|------------|
| **secubox-monitoring** | Dashboard Grafana/Prometheus intégré | Moyenne |
| **secubox-mail** | Relais mail sécurisé | Haute |

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

## Wishlist — Documentation

| Page | Statut | Notes |
|------|--------|-------|
| Guide développeur | ✅ Complet | `docs/PORTING-GUIDE.md` |
| API Reference | ✅ Complet | 2000+ endpoints documentés |
| Traductions | 🔄 En cours | DE partiel, ZH partiel |
| Tutoriels vidéo | ⬜ Wishlist | Pas de priorité actuelle |

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

*Dernière mise à jour : 2026-05*
