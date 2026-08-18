<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Sponsor-a-Port — Mécénat de portage

Vous pouvez sponsoriser le portage de SecuBox-Deb vers une nouvelle cible matérielle. Chaque portage sponsorisé produit un livrable concret, public, et crédité.

---

## Concept

Un sponsor finance le travail de portage. En échange, il reçoit un livrable technique complet et un crédit public. Ce n'est pas de la publicité — c'est du mécénat technique avec contrepartie limitée.

Le travail de portage est publié sous la même licence que le projet. Le sponsor ne détient aucun droit exclusif sur le code produit.

---

## Trois échelles de portage

### Port léger — ~3 000 €

**Contexte** : Carte avec bon support mainline, device tree complet ou quasi-complet, pas de patches kernel nécessaires.

**Livrables** :
- Profil profile-generator YAML
- Image bootable testée
- Rapport de benchmark (CPU, réseau, I/O)
- Documentation installation sur wiki
- Entrée Hardware-Matrix avec statut "Tested"

**Exemple** : Raspberry Pi 5, nouvelle révision ESPRESSObin

### Port standard — ~6 000 €

**Contexte** : Device tree à compléter, 1-2 patches kernel, intégration U-Boot/Tow-Boot standard.

**Livrables** :
- Tout le port léger, plus :
- Patches kernel upstream-ready
- Configuration U-Boot/Tow-Boot validée
- Tests de régression automatisés
- Maintenance pendant 2 cycles de release

**Exemple** : NanoPi R6S, Banana Pi BPI-R4 / BPI-R4 Pro

### Port lourd — ~12 000 €+

**Contexte** : Device tree from scratch, drivers custom, U-Boot custom, matériel complexe (10GbE+, switch fabric).

**Livrables** :
- Tout le port standard, plus :
- Device tree complet upstream-ready
- Drivers spécifiques si nécessaire
- Documentation architecture hardware
- Maintenance pendant 4 cycles de release
- Canal support dédié pendant le développement

**Exemple** : MACCHIATObin, HoneyComb LX2K

---

## Livrables détaillés

Chaque portage sponsorisé inclut au minimum :

| Livrable | Description |
|----------|-------------|
| **Device Tree** | DT upstream-ready ou patches documentés |
| **Profile YAML** | Configuration profile-generator complète |
| **Image bootable** | .img.gz prête au flash, testée |
| **Benchmark report** | CPU (sysbench), réseau (iperf3), I/O (fio) |
| **Documentation** | Page wiki Installation + Troubleshooting |
| **Commits** | Range git public, changelog |
| **Release tag** | Version release avec le port inclus |

---

## Contreparties sponsor

Les contreparties sont limitées et non publicitaires :

| Contrepartie | Opt-in | Description |
|--------------|--------|-------------|
| **Crédit Acknowledgments** | Oui | Nom/organisation dans la section sponsors |
| **Crédit README port** | Oui | "Sponsored by [X]" dans la doc du port |
| **Logo** | Opt-in | Logo sur la page wiki du port (PNG, max 200px) |
| **Canal dédié** | Automatique | Matrix/Signal/email pendant le développement |
| **Accès preview** | Automatique | Images de test avant release publique |

Ce qui n'est **pas** inclus :
- Mention sur la page d'accueil du projet
- Branding sur les images ou l'interface
- Droits exclusifs ou priorité de support
- Publicité dans les releases ou changelogs

---

## Wishlist active

Cibles matérielles recherchant un sponsor :

| Carte | SoC | Complexité | Budget estimé | Intérêt |
|-------|-----|------------|---------------|---------|
| **MACCHIATObin** | Armada 8040 | Lourd | ~12 000 € | Server-grade 10GbE |
| **HoneyComb LX2K** | LX2160A | Lourd | ~15 000 € | 25GbE, NVMe |
| **Banana Pi BPI-R4** | MT7988A | Standard | ~5 000 € | Edge/budget, 4 GB, 4× GbE |
| **Banana Pi BPI-R4 Pro** | MT7988A | Standard | ~6 000 € | MOCHAbin-class, 8 GB, 4× 2.5GbE |
| **NanoPi R6S** | RK3588S | Standard | ~5 000 € | Rockchip compact |
| **Traverse Ten64** | LS1088A | Lourd | ~10 000 € | Open hardware |

Pour proposer une nouvelle cible, ouvrez une issue GitHub avec le tag `hardware-request`.

---

## Process

1. **Contact** — Email à `devel@cybermind.fr` ou issue GitHub
2. **Scoping** — Évaluation de la complexité, définition du périmètre
3. **Devis** — Proposition écrite avec livrables et planning indicatif
4. **Contrat** — Document de parrainage (voir [[Fiscal-Notes]])
5. **Développement** — Itérations avec accès preview
6. **Livraison** — Release publique, crédit, documentation
7. **Maintenance** — Support pendant N cycles selon l'échelle

---

## Cadrage juridique

Le financement de portage est structuré comme du **parrainage** (sponsoring) et non comme du mécénat au sens fiscal. CyberMind est une entreprise individuelle qui facture la prestation. Le sponsor peut déduire cette charge dans les conditions habituelles.

Pour plus de détails sur les implications fiscales, voir **[[Fiscal-Notes]]**.

---

## Liens

- **[[Hardware-Matrix]]** — Statut des cibles actuelles
- **[[Financing-Model]]** — Modèle de financement global
- **[[Acknowledgments]]** — Crédits sponsors existants
- **[[Fiscal-Notes]]** — Cadrage parrainage/mécénat
