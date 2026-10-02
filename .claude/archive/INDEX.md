<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Archives — index (ne lire que sur demande)

Déplacées **à l'identique** le 2026-10-02 (#1863) depuis `WIP.md`, `HISTORY.md`, `TODO.md`
(master `8af868a51`). Un fichier = un mois ; « sans-date » = sections dont le titre ne porte
pas de date (anciennes « Session N »). Pour retrouver quelque chose : `grep -rn "<mot>" .claude/archive/`
puis lire seulement le fichier du mois — jamais un dossier entier.

## Preuve de zéro perte

`python3 .claude/archive/reassembler.py --actif-ref <commit-de-découpe>` reconstitue chaque
fichier d'origine depuis l'archive (et les sections restées actives dans `TODO.md`) et compare
son SHA-256 à l'original : **WIP, HISTORY et TODO sortent identiques à l'octet**
(484 849 / 516 468 / 88 952 octets). Empreintes d'origine et de chaque section : `manifest.json`.

## Contenu

### WIP — original 484 849 octets  9904 lignes

| Fichier | Sections | Lignes |
|---|---|---|
| `archive/WIP/2026-04.md` | 9 | 247 |
| `archive/WIP/2026-05.md` | 28 | 973 |
| `archive/WIP/2026-06.md` | 23 | 1107 |
| `archive/WIP/2026-07.md` | 30 | 444 |
| `archive/WIP/2026-08.md` | 26 | 872 |
| `archive/WIP/2026-09.md` | 34 | 510 |
| `archive/WIP/sans-date.md` | 133 | 5739 |

### HISTORY — original 516 468 octets  9179 lignes

| Fichier | Sections | Lignes |
|---|---|---|
| `archive/HISTORY/2026-03.md` | 9 | 209 |
| `archive/HISTORY/2026-04.md` | 8 | 868 |
| `archive/HISTORY/2026-05.md` | 29 | 3971 |
| `archive/HISTORY/2026-06.md` | 42 | 1790 |
| `archive/HISTORY/2026-07.md` | 29 | 524 |
| `archive/HISTORY/2026-08.md` | 17 | 517 |
| `archive/HISTORY/2026-09.md` | 23 | 1221 |
| `archive/HISTORY/sans-date.md` | 1 | 72 |

### TODO — original 88 952 octets  1643 lignes

| Fichier | Sections | Lignes | Cases ouvertes |
|---|---|---|---|
| `archive/TODO/2026-06.md` | 3 | 157 | 20 |
| `archive/TODO/2026-07.md` | 9 | 168 | 36 |
| `archive/TODO/2026-08.md` | 9 | 220 | 66 |
| `archive/TODO/sans-date.md` | 17 | 966 | 110 |

Restées actives dans `TODO.md` : 7 sections (≥ 2026-09-01).

