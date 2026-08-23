<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# Zanimalos — contrat du pack (archive ZIP compatible SecuBox)

Fichier de référence **à fournir au générateur du ZIP**. Un pack qui respecte
ce contrat est directement consommable par SecuBox (billets, bbs) et, à terme,
par l'upload de mise à jour à chaud.

## 1. Structure de l'archive

```
Zanimalos_Signal_Stickers.zip
├── stickers/
│   ├── 01_peek.webp        (ou .png)
│   ├── 02_poke.webp
│   ├── …
│   └── 32_solko.webp
├── manifest.json           ← OBLIGATOIRE (voir §3)
├── cover.webp              ← facultatif
├── emoji_mapping.csv       ← facultatif (numero,nom,role,emoji,fichier)
└── preview_contact_sheet.png  ← facultatif
```

- Un seul dossier `stickers/` à la racine (ou à la racine directe).
- **Exactement 32** fichiers image.

## 2. Les 32 personnages — nommage FIXE

Le nom et le numéro sont **canoniques et immuables** : c'est ce qui relie l'art
aux rôles de statut/type dans SecuBox. Ne pas renommer, ne pas réordonner.

| NN | fichier            | NN | fichier             | NN | fichier            | NN | fichier            |
|----|--------------------|----|---------------------|----|--------------------|----|--------------------|
| 01 | `01_peek`          | 09 | `09_orin`           | 17 | `17_bruma`         | 25 | `25_gazou`         |
| 02 | `02_poke`          | 10 | `10_mav`            | 18 | `18_luma`          | 26 | `26_nala`          |
| 03 | `03_pink`          | 11 | `11_kip`            | 19 | `19_vex`           | 27 | `27_eko`           |
| 04 | `04_pong`          | 12 | `12_grom`           | 20 | `20_juna`          | 28 | `28_huko`          |
| 05 | `05_noa`           | 13 | `13_selia`          | 21 | `21_pilo`          | 29 | `29_zeph`          |
| 06 | `06_kragzouy`      | 14 | `14_tikko`          | 22 | `22_mosh`          | 30 | `30_mina`          |
| 07 | `07_lyra`          | 15 | `15_neri`           | 23 | `23_razo`          | 31 | `31_tala`          |
| 08 | `08_ziri`          | 16 | `16_wodi`           | 24 | `24_olli`          | 32 | `32_solko`         |

- Motif du nom : `NN_nom` — `NN` sur **deux chiffres** (`01`…`32`), `nom` en
  **minuscules ASCII** (accents retirés : `selia`, `neri`).
- Extension : `.webp` **ou** `.png` (RGBA). WebP recommandé (plus léger).

## 3. `manifest.json` (obligatoire)

```json
{
  "title": "Zanimalos — Bestiaire surnaturel",
  "author": "Zanimalos / AletheiaVox",
  "count": 32,
  "format": "WebP RGBA",
  "size": "512x512",
  "stickers": [
    { "number": 1, "name": "Peek", "role": "Observateur", "emoji": "🔎", "file": "01_peek.webp" },
    { "number": 2, "name": "Poke", "role": "Bricoleur",   "emoji": "🛠️", "file": "02_poke.webp" }
  ]
}
```

- `stickers[]` : 32 entrées, ordre 1→32.
- `number` (1..32), `name` (Capitalisé), `role` (libre), `emoji`, `file`
  (chemin relatif dans `stickers/`).

## 4. Contraintes d'IMAGE (pour un rendu propre)

- **512×512 px**, RGBA, **fond transparent**.
- Le personnage **remplit le cadre** : padding transparent ≤ **~12 %** de
  chaque côté (le v3 « bestiaire surnaturel » respecte ce point ; l'ancien
  « canonique » avec ~36 % de marge rendait les vignettes minuscules — à éviter).
- Halo/contour sticker autorisé, inclus dans le cadre.
- Pas de texte de numéro incrusté (le `NN_` du nom suffit).

## 5. Où l'art atterrit dans SecuBox

- `packages/secubox-billets/api/static/stickers/zanimalos/NN_NAME.png`
- `packages/secubox-bbs/internal/web/static/stickers/zanimalos/NN_NAME.png`
  (converti en PNG 256 à l'ingestion ; embarqué via `go:embed`).

Mapping actuel piloté par le nom canonique :
- **statut** (billets) : publié=`18_LUMA`, brouillon=`14_TIKKO`, archivé=`15_NERI`.
- **type** (billets+bbs) : vidéo=`14_TIKKO`, audio=`25_GAZOU`, livre=`15_NERI`,
  conférence=`16_WODI`, lien=`01_PEEK`, image=`03_PINK`, discussion=`07_LYRA`.

Tant que les **32 noms** sont respectés, une nouvelle version d'art se substitue
sans toucher au code.
