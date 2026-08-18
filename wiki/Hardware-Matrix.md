<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Hardware Matrix — BYOH

SecuBox-Deb fonctionne sur du matériel que vous possédez ou achetez directement chez le fournisseur de votre choix. Cette page liste les cibles testées et leur statut de support.

**Principe BYOH** : Bring Your Own Hardware. Pas de vente de kits, pas d'affiliation commerciale. Les liens pointent vers les fournisseurs officiels à titre informatif — aucun lien n'est tracké.

---

## Statuts de support

| Badge | Statut | Signification |
|-------|--------|---------------|
| ![Tested](https://img.shields.io/badge/status-tested-0A5840?style=flat-square) | **Tested & Supported** | Testé par le mainteneur, support actif, mises à jour régulières |
| ![Community](https://img.shields.io/badge/status-community-104A88?style=flat-square) | **Community Ported** | Porté par la communauté, testé mais support limité |
| ![Experimental](https://img.shields.io/badge/status-experimental-C04E24?style=flat-square) | **Experimental** | En cours de portage, non recommandé pour production |
| ![Wishlist](https://img.shields.io/badge/status-wishlist-6B6963?style=flat-square) | **Wishlist** | Demandé, en attente de sponsor ou de matériel |

---

## Matrice principale

> **Note prix** : Prix indicatifs constatés en 2025-2026, hors frais de port. Les prix varient selon le fournisseur et la disponibilité. Aucun lien d'affiliation.

### GlobalScale / SolidRun — Marvell Armada

| Carte | SoC | RAM | Réseau | Prix | Statut | Notes |
|-------|-----|-----|--------|------|--------|-------|
| [**MOCHAbin**](https://globalscaletechnologies.com/product/mochabin/) | Armada 7040 | 4 GB | 4× GbE + 10GbE SFP+ | ~350 € | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Cible principale Full |
| [**MOCHAbin**](https://globalscaletechnologies.com/product/mochabin/) | Armada 7040 | 8 GB | 4× GbE + 10GbE SFP+ | ~450 € | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Full profile, DPI |
| [**ESPRESSObin v7**](https://globalscaletechnologies.com/product/espressobin-v7/) | Armada 3720 | 1 GB | 3× GbE (Topaz) | ~50 € | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Cible Lite entry |
| [**ESPRESSObin v7**](https://globalscaletechnologies.com/product/espressobin-v7/) | Armada 3720 | 2 GB | 3× GbE (Topaz) | ~70 € | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Cible Lite, DDR4 |
| [**ESPRESSObin Ultra**](https://globalscaletechnologies.com/product/espressobin-ultra/) | Armada 3720 | 1-2 GB | 3× GbE + Wi-Fi | ~100 € | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Lite+ Wi-Fi intégré |
| [**ClearFog Base**](https://www.solid-run.com/arm-servers-networking-platforms/clearfog-base/) | Armada 388 | 1 GB | 2× GbE | ~150 € | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | Compact, mPCIe |
| [**ClearFog Pro**](https://www.solid-run.com/arm-servers-networking-platforms/clearfog-pro/) | Armada 388 | 1 GB | 6× GbE + SFP | ~220 € | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | Switch intégré |
| [**MACCHIATObin**](https://www.solid-run.com/arm-servers-networking-platforms/macchiatobin/) | Armada 8040 | 16 GB | 4× 10GbE | ~800 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Server-grade |

### SBC ARM64 divers

| Carte | SoC | RAM | Réseau | Prix | Statut | Notes |
|-------|-----|-----|--------|------|--------|-------|
| [**Raspberry Pi 400**](https://www.raspberrypi.com/products/raspberry-pi-400/) | BCM2711 | 4 GB | 1× GbE | ~80 € | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | USB-Eth recommandé |
| [**NanoPi R6S**](https://www.friendlyelec.com/index.php?route=product/product&product_id=289) | RK3588S | 8 GB | 2× 2.5GbE | ~140 € | ![Experimental](https://img.shields.io/badge/-experimental-C04E24?style=flat-square) | En test |
| [**Banana Pi BPI-R4**](https://docs.banana-pi.org/en/BPI-R4/BananaPi_BPI-R4) | MT7988A | 4 GB | 4× GbE + 2× 10G SFP | ~110 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Edge/budget |
| [**Banana Pi BPI-R4 Pro**](https://docs.banana-pi.org/en/BPI-R4_Pro/BananaPi_BPI-R4_Pro) | MT7988A | 4 GB | 4× 2.5GbE + 2× 10G SFP+ | ~150 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Candidat medium |
| [**Banana Pi BPI-R4 Pro**](https://docs.banana-pi.org/en/BPI-R4_Pro/BananaPi_BPI-R4_Pro) | MT7988A | 8 GB | 4× 2.5GbE + 2× 10G SFP+ | ~180 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | MOCHAbin-class |
| [**HoneyComb LX2K**](https://www.solid-run.com/arm-servers-networking-platforms/honeycomb-lx2/) | LX2160A | 64 GB | 4× 10GbE + 2× 25GbE | ~900 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Server-grade |
| [**NanoPC-T6**](https://www.friendlyelec.com/index.php?route=product/product&product_id=292) | RK3588 | 16 GB | 2× 2.5GbE | ~200 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Rockchip flagship |
| [**Traverse Ten64**](https://www.traverse.com.au/products/ten64/) | LS1088A | 8 GB | 8× GbE + 2× 10G SFP+ | ~650 € | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | Open hardware |

### x86_64

| Cible | Type | RAM | Réseau | Coût | Statut | Notes |
|-------|------|-----|--------|------|--------|-------|
| [**VirtualBox**](https://www.virtualbox.org/) | VM | 2+ GB | Virtio/E1000 | Gratuit | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | `create-vbox-vm.sh` |
| [**QEMU**](https://www.qemu.org/) | VM | 2+ GB | Virtio | Gratuit | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | `run-qemu.sh` |
| **Bare metal x64** | PC | 4+ GB | Intel/Realtek GbE | Variable | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Live USB bootable |
| [**Proxmox**](https://www.proxmox.com/en/proxmox-virtual-environment) | VM | 2+ GB | Virtio | Gratuit | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | Import qcow2 |

---

## Profils d'usage

### Edge / Mobile

Déploiement nomade, consommation minimale, pas de ventilateur.

- ESPRESSObin v7 (recommandé)
- ClearFog Base
- Raspberry Pi 400

### Appliance PME (small)

Routeur/firewall pour petite structure, 10-50 utilisateurs.

- ESPRESSObin Ultra (avec Wi-Fi)
- ClearFog Pro
- Banana Pi BPI-R4 (4 GB, edge/budget)
- NanoPi R6S (en test)

### Appliance PME (medium)

Capacité mémoire accrue, DPI, 50-200 utilisateurs.

- MOCHAbin (recommandé)
- Banana Pi BPI-R4 Pro (8 GB, candidat sérieux)
- NanoPC-T6 (à venir)

### Gateway Entreprise

Inspection DPI haute performance, clustering, 10GbE.

- MOCHAbin (recommandé)
- MACCHIATObin (à venir)
- HoneyComb LX2K (à venir)

### Test / Développement

Validation logicielle, CI/CD, formation.

- VirtualBox (recommandé pour débuter)
- QEMU (ARM ou x64)
- Proxmox

---

## Notes techniques

**Kernel** : SecuBox-Deb utilise le kernel 6.6 LTS mainline avec device trees upstream Marvell. Pas de patches out-of-tree sauf exception documentée.

**Bootloader** : U-Boot ou Tow-Boot selon la carte. Les images fournissent un boot média ou permettent le flash eMMC.

**Profil YAML** : Chaque carte dispose d'un profil profile-generator définissant la configuration réseau, les modules activés, et les paramètres spécifiques au matériel.

---

## Liens

- **[[Sponsor-a-Port]]** — Pour financer le portage d'une cible Wishlist
- **[[Installation]]** — Guide d'installation général
- **[[ARM-Installation]]** — Procédure spécifique ARM/U-Boot
- **[[Roadmap]]** — État des portages en cours
