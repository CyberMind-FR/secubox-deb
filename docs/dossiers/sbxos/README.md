<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Références SBX OS — documents de conception

## Ce qui est ici, et ce qui n'y est pas

Le guide 16 pages pèse **48 Mo**. Il n'est pas versé dans le dépôt : un
binaire de cette taille alourdit chaque clone pour tout le monde, et il
n'apporterait rien qu'une empreinte ne dise déjà.

Seul le compagnon, léger, est archivé. Les autres sont identifiés par leur
empreinte — ce qui suffit à savoir **quelle version** une analyse a examinée,
qui est la seule chose dont un audit a besoin.

| document | pages | taille | SHA-256 |
|---|---:|---:|---|
| `SecuBox-DEB_Guide_16_pages_Mockup_v3.pdf` | — | 47.2 Mo | `504f1330a9e41817bef4246d…` |
| `LDXOS-Hall-Sketchbook.pdf` | — | 10.2 Mo | `7e69b5d63af7263712a730e2…` |
| `SBX_OS_Compagnon_Mockup_v1.pdf` | — | 0.0 Mo | `7977b8e05dda938ac358b834…` |

## Le guide 16 pages est la référence produit

Il définit le **reverse design** : ses maquettes d'interface fixent la cible
que l'implémentation doit atteindre. Analyse dans
[`../../audits/ANALYSE-DOCUMENTS-REFERENCE.md`](../../audits/ANALYSE-DOCUMENTS-REFERENCE.md).

## Ce qui lui manque, et c'est important

**Il ne contient aucun texte extractible.** 16 pages, 18 images, zéro
caractère récupérable.

Ce n'est pas un détail de forme. Un document de référence que seule une
lecture humaine peut consulter n'est ni cherchable, ni comparable d'une
version à l'autre, ni citable depuis une issue, ni accessible aux lecteurs
d'écran — et il échappe à toute chaîne automatique.

La démonstration est faite : ce document existait et était la référence
pendant qu'un audit interne affirmait le contraire, faute de pouvoir le lire.

**À produire** : une version texte ou Markdown du même contenu, à côté. Le
PDF reste la forme diffusée ; le texte devient la forme vérifiable. C'est ce
que fait déjà `docs/dossiers/anssi/` pour le dossier ANSSI.
