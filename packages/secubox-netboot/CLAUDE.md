<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — module `secubox-netboot`

> Réf. : #737 « secubox-netboot: provisioning réseau + overlay U-Boot + auto-flash A/B »
> Cibles : MOCHAbin (Armada 7040, AP806) · ESPRESSObin v7 / Ultra (Armada 3720)
> Licence : LicenseRef-CMSD-1.0 · Doctrine CSPN (intégrité par signature, A/B, audit)

Module de **provisioning et de boot réseau** des appliances SecuBox. Il héberge les
images release, fournit un **overlay U-Boot** (fonctions manquantes : HTTP(S),
FIT-signature) chainloadé par le U-Boot usine, gère un **auto-flash A/B** quand
l'usine est trop ancienne, et expose une **UI de suivi/contrôle** + des **triggers**.

## 0. État matériel de référence (gk2 = MOCHAbin 8GB)

| Élément | Valeur |
|---------|--------|
| SoC | `marvell,armada7040` (AP806 quad), `globalscale-mochabin-8gb` |
| Firmware | TF-A **v2.9 (release)**, kernel 6.12.85 (build récent, ≠ usine) |
| Bootloader | SPI-NOR `mtd0 "firmware"` (3.9 MB = TF-A + U-Boot) |
| Env U-Boot | SPI-NOR `mtd2 "u-boot-env"` (64 KB) — `fw_env.config` à caler |
| eMMC | `mmcblk0` : p1 `/boot` (256 M), p2 `/` (14.4 G) |
| **Slots A/B** | eMMC `mmcblk0boot0` / `mmcblk0boot1` (4 MB chacun) |
| Outils | `mkimage`/`dumpimage` (FIT), `fw_printenv`/`fw_setenv` présents |

> ⚠️ Le média de boot **réel** (SPI vs eMMC) dépend des straps/DIP de la board.
> À confirmer board par board avant tout flash. Voir `docs/PHASE2-uboot-overlay.md`.

## 1. Doctrine (NON négociable)

- **Jamais flasher le seul slot primaire à l'aveugle.** Tout flash de bootloader
  passe par un slot **secondaire** (A/B) + bascule + fallback usine + watchdog.
- **Intégrité par signature, pas confiance du transport.** Image/U-Boot servis en
  HTTP simple acceptés *uniquement* si vérifiés par **FIT signature**
  (`CONFIG_FIT_SIGNATURE`, clé publique embarquée dans le 2ᵉ U-Boot / TF-A).
- **Overlay d'abord, flash en dernier recours.** On ajoute les fonctions via un
  2ᵉ U-Boot chainloadé tant que l'usine sait charger un payload ; on ne reflash
  l'usine que si elle ne sait même pas chainloader.
- **Tout par board.** DTS, driver réseau, adresses de chargement diffèrent
  (mochabin ≠ espressobin-v7 ≠ ultra). Réutiliser `board/<name>/`.
- **Audit immuable** (CSPN) : chaque décision overlay/flash/boot journalisée
  append-only dans `/var/log/secubox/netboot/audit.log`.
- **Confirmation opérateur** explicite pour tout flash ; alim stable requise.

## 2. Arborescence cible

```
packages/secubox-netboot/
├── CLAUDE.md                       # ce fichier
├── docs/
│   ├── PHASE2-uboot-overlay.md     # spec de l'overlay 2ᵉ U-Boot (chainload)
│   └── boot-flow.md                # chaîne BootROM→TF-A→U-Boot usine→overlay→OS
├── api/main.py                     # FastAPI : inventaire, catalogue, contrôle
├── sbin/
│   ├── secubox-netboot-probe       # détecte U-Boot ver + capacités + média boot
│   ├── secubox-netboot-overlay     # pose/retire l'overlay (env + FIT en /boot)
│   ├── secubox-netboot-flash       # auto-flash A/B (slot secondaire, gated)
│   └── secubox-netboot-triggers    # exécute les hooks de cycle de vie
├── board/<name>/                   # u-boot defconfig + adresses + DTS par board
├── tftp/                           # boot.scr, FIT overlays servis
├── systemd/                        # secubox-netboot.service + tftp/http
├── www/netboot/                    # UI suivi/contrôle
├── menu.d/NN-netboot.json          # catégorie "boot"
└── debian/                         # control/rules/postinst/...
```

## 3. Surface API (cible)

| Méthode | Path | Rôle |
|---------|------|------|
| GET | `/api/v1/netboot/inventory` | boards : id, modèle, U-Boot ver, image OS, slot actif, dernier boot |
| GET | `/api/v1/netboot/images` | catalogue release (version, board, signature, url) |
| GET | `/api/v1/netboot/probe` | capacités U-Boot de CETTE board (wget/FIT/bootm…) |
| POST | `/api/v1/netboot/overlay/apply` | poser l'overlay 2ᵉ U-Boot (gated) |
| POST | `/api/v1/netboot/overlay/revert` | retirer l'overlay → boot usine |
| POST | `/api/v1/netboot/flash` | auto-flash A/B (confirmation + signature) |
| POST | `/api/v1/netboot/rollback` | revenir au slot précédent |
| GET | `/api/v1/netboot/status/{board}` | live : fetch/flash progress, console |

Auth JWT obligatoire (`Depends(auth.require_jwt)`). Socket `/run/secubox/netboot.sock`,
servi **en standalone** (pas in-process aggregator : opérations lourdes/bloquantes).

## 4. Réutilisation de l'existant

- **Eye-Remote boot-media / TFTP** (`/api/v1/eye-remote/boot-media/*`, double-buffer
  swap/rollback) = socle direct pour servir et basculer les artefacts de boot.
- **CI `image/build-image.sh`** = source des images release ; ajouter l'étape
  *signature* + *publication* vers l'hôte HTTP netboot.
- **`board/<name>/`** = configs board déjà présentes (mochabin, espressobin-v7/ultra).
- **PARAMETERS double-buffer / 4R** = modèle pour active/shadow/rollback des configs boot.

## 5. Hors périmètre P2

P0 (inventaire/catalogue read-only), P1 (`boot.scr` TFTP fonctions-usine), P3
(auto-flash A/B + triggers), P4 (signature bout-en-bout + audit) — voir #737.
P2 se concentre sur l'**overlay 2ᵉ U-Boot chainloadé** et son cycle pose/rollback.
