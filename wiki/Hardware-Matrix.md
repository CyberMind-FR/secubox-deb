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

### GlobalScale Marvell Armada

| Carte | SoC | RAM | Réseau | Statut | Kernel | Notes |
|-------|-----|-----|--------|--------|--------|-------|
| **MOCHAbin** | Armada 7040 | 4-8 GB | 4× GbE + 10GbE SFP+ | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | 6.6 LTS | Cible principale Full profile |
| **ESPRESSObin v7** | Armada 3720 | 1-2 GB | 3× GbE (Topaz switch) | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | 6.6 LTS | Cible Lite, DDR4 |
| **ESPRESSObin Ultra** | Armada 3720 | 1-2 GB | 3× GbE + Wi-Fi | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | 6.6 LTS | Lite+ avec Wi-Fi intégré |
| **ClearFog Base** | Armada 388 | 1 GB | 2× GbE | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | 6.6 LTS | Compact, mPCIe |
| **ClearFog Pro** | Armada 388 | 1 GB | 6× GbE + SFP | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | 6.6 LTS | Switch intégré |
| **MACCHIATObin** | Armada 8040 | 16 GB | 4× 10GbE | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | — | Server-grade, sponsor recherché |

### SBC ARM64 divers

| Carte | SoC | RAM | Réseau | Statut | Kernel | Notes |
|-------|-----|-----|--------|--------|--------|-------|
| **Raspberry Pi 400** | BCM2711 | 4 GB | 1× GbE | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | 6.6 LTS | USB-Ethernet recommandé |
| **NanoPi R6S** | RK3588S | 8 GB | 2× 2.5GbE | ![Experimental](https://img.shields.io/badge/-experimental-C04E24?style=flat-square) | 6.6 | En test |
| **Banana Pi BPI-R4** | MT7988A | 4 GB | 4× GbE + 2× 10G SFP | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | — | Edge/budget, sponsor recherché |
| **Banana Pi BPI-R4 Pro** | MT7988A | 4-8 GB | 4× 2.5GbE + 2× 10G SFP+ | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | — | Candidat MOCHAbin-class |
| **HoneyComb LX2K** | LX2160A | 64 GB | 4× 10GbE + 2× 25GbE | ![Wishlist](https://img.shields.io/badge/-wishlist-6B6963?style=flat-square) | — | Server-grade, sponsor recherché |

### x86_64

| Cible | Type | RAM | Réseau | Statut | Notes |
|-------|------|-----|--------|--------|-------|
| **VirtualBox** | VM | 2+ GB | Virtio/E1000 | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Script `create-vbox-vm.sh` |
| **QEMU** | VM | 2+ GB | Virtio | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Script `run-qemu.sh` |
| **Bare metal x64** | PC | 4+ GB | Intel/Realtek GbE | ![Tested](https://img.shields.io/badge/-tested-0A5840?style=flat-square) | Live USB bootable |
| **Proxmox** | VM | 2+ GB | Virtio | ![Community](https://img.shields.io/badge/-community-104A88?style=flat-square) | Import qcow2 |

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
