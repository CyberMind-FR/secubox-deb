# Gabarit — Livret agrafé A5

Livret A5 (148 × 210 mm) en piqûre à cheval (deux agrafes sur le pli) :
livret d'exposition, parcours de visite, monographie courte, programme.
De 8 à 48 pages. Il reprend le gabarit [A5](../a5/README.md) avec une marge
intérieure réduite (le cahier s'ouvre à plat) et une attention particulière à
la chasse.

Grille SVG associée :
[`grille-livret-a5-double-page.svg`](../../assets/grids/grille-livret-a5-double-page.svg)

## Fiche technique

| Paramètre | Valeur |
|-----------|--------|
| Format fini | 148 × 210 mm (portrait), soit une feuille A4 pliée en deux |
| Format avec fond perdu | 154 × 216 mm par page ; 302 × 216 mm par double page à plat |
| Fond perdu | 3 mm sur les quatre côtés de chaque page |
| Zone sûre | 5 mm depuis la coupe ; 7 mm sur le bord extérieur des pages centrales au-delà de 48 pages |
| Marges | Tête 16 mm · Pied 22 mm · Intérieure 12 mm · Extérieure 18 mm |
| Surface de composition | 118 × 172 mm |
| Colonnes | 1 colonne de 118 mm (texte) ; grille de 3 modules de 36,67 mm, gouttière 4 mm (images) ; 2 colonnes de 57 mm pour les pages finales |
| Grille de ligne de base | 13 pt à partir de la marge de tête ; 37 lignes par page |
| Corps de texte | 10 / 13 pt Serif, ≈ 70 caractères par ligne |
| Résolution des images | 300 ppp effectifs ; pleine page à fond perdu ≥ 1 820 × 2 552 px ; pleine ouverture ≥ 3 570 × 2 552 px |
| Espace couleur | CMJN, ISO Coated v2 300 % (FOGRA39) par défaut ; profil de l'imprimeur en impression numérique |
| Papier conseillé | Intérieur : couché mat 135 g/m² (ou 115 g/m² au-delà de 32 pages) ; couverture : couché mat 250 g/m² ; « autocouverture » (même papier partout, 170 g/m²) pour un livret de 8 à 16 pages |
| Reliure | Piqûre à cheval, 2 agrafes ; agrafes à œillets (pour classeur) en option |
| Nombre de pages | **Multiple de 4 obligatoire** ; de 8 à 48 pages (64 au maximum sur papier fin) ; couverture comptée à part (4 pages) ou intégrée (autocouverture) |
| Chasse | ≈ 0,15 mm par feuille de 135 g/m² ; compensation à demander à l'imprimeur au-delà de 32 pages |

## Schéma de la double page

```text
 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
 ¦ ┌───────────────────────────────────┬───────────────────────────────────┐ ¦
 ¦ │              16                   ╎                  16               │ ¦
 ¦ │      ┌───────────────┐            ╎            ┌───────────────┐      │ ¦
 ¦ │  18  │               │  12        ╎        12  │               │  18  │ ¦
 ¦ │      │               │            ╎            │               │      │ ¦
 ¦ │      │    verso      │            ╎            │    recto      │      │ ¦
 ¦ │      │   118 × 172   │            ╎            │   118 × 172   │      │ ¦
 ¦ │      │               │            ╎            │               │      │ ¦
 ¦ │      │   37 lignes   │            ╎            │   37 lignes   │      │ ¦
 ¦ │      │               │            ╎            │               │      │ ¦
 ¦ │      └───────────────┘            ╎            └───────────────┘      │ ¦
 ¦ │  12                 22            ╎            22                 13  │ ¦
 ¦ └───────────────────────────────────┴───────────────────────────────────┘ ¦
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                                       ↑ pli et agrafes
```

Le pli d'un livret agrafé est un vrai pli (pas un dos) : une image en pleine
ouverture y est continue, sans recouvrement, à condition d'être placée sur
une double page qui tombe **sur la même feuille** (les pages centrales, ou
toute double page dont les deux pages sont imposées côte à côte). Sur les
autres doubles pages, les deux moitiés sont imprimées sur deux feuilles
différentes : un décalage de 0,5 à 1 mm au pli est possible. Réserver les
pleines ouvertures exigeantes (lignes horizontales, visages) à la double page
centrale.

## Chasse

```text
 Livret de 24 pages = 6 feuilles A4 pliées, imbriquées

 feuille 1 : pages  1 -  2 | 23 - 24   (extérieure)
 feuille 2 : pages  3 -  4 | 21 - 22
 feuille 3 : pages  5 -  6 | 19 - 20
 feuille 4 : pages  7 -  8 | 17 - 18
 feuille 5 : pages  9 - 10 | 15 - 16
 feuille 6 : pages 11 - 12 | 13 - 14   (centrale, dépasse le plus avant rognage)

 Après rognage, la marge extérieure des pages 12–13 est plus courte que celle
 des pages 1–24 d'environ 6 × 0,15 = 0,9 mm.
```

| Nombre de pages (135 g/m²) | Chasse totale | Mesure de précaution |
|----------------------------|---------------|----------------------|
| 8 à 16 | ≤ 0,6 mm | Aucune ; la zone sûre de 5 mm suffit |
| 20 à 32 | 0,8 à 1,2 mm | Aucune ; demander la compensation si des cadres ou folios doivent être parfaitement alignés d'une page à l'autre |
| 36 à 48 | 1,4 à 1,8 mm | Zone sûre extérieure de 7 mm sur les pages centrales ; compensation demandée à l'imprimeur |
| Plus de 48 | > 1,8 mm | Passer en 115 g/m² ou en dos carré collé |

## Couverture

| Option | Description | Quand |
|--------|-------------|-------|
| Couverture séparée | 4 pages (C1, C2, C3, C4) en 250 g/m², exportées en pages simples ou à plat (C4 + C1, C2 + C3) selon l'imprimeur | Livret de 16 pages et plus, tenue en main, vente |
| Autocouverture | La couverture est constituée des 4 premières et dernières pages du même papier ; le livret compte alors ses pages en incluant la couverture (par exemple 24 pages dont 4 de couverture) | Livret court, gratuit, économique |

Sur un livret agrafé, C2 porte les mentions légales et crédits, C3 les
remerciements et contacts, C4 l'accroche, le logo, le prix et le code-barres.
Il n'y a pas de dos : le titre n'est pas répété sur la tranche.

## Structure type (24 pages + couverture)

Le chemin de fer complet correspondant figure dans
[assets/examples/chemin-de-fer-livret-a5.md](../../assets/examples/chemin-de-fer-livret-a5.md).

| Pages | Contenu |
|-------|---------|
| C1 | Titre, image à fond perdu, cartouche éditeur |
| C2 | Mentions légales, crédits |
| 1 | Faux-titre ou sommaire (recto) |
| 2–3 | Avant-propos, carte |
| 4–5 | Ouverture du chapitre 1 |
| 6–21 | Corps, 2 chapitres, 2 respirations dont la double page centrale 12–13 |
| 22–23 | Épilogue, chronologie |
| 24 | Sources, index |
| C3 | Remerciements, contacts |
| C4 | Accroche, code-barres |

## Configuration du document

| Logiciel | Réglages |
|----------|----------|
| InDesign | Nouveau document : A5, pages en vis-à-vis, nombre de pages multiple de 4, marges tête 16 / pied 22 / intérieure 12 / extérieure 18 mm, colonnes 1, fond perdu 3 mm ; grille de ligne de base 13 pt, début à 16 mm ; gabarit « Images » 3 colonnes / 4 mm. Exporter en pages simples : l'imposition est faite par l'imprimeur (ou par « Fichier › Imprimer un livret » pour une épreuve de bureau seulement) |
| Scribus | Fichier › Nouveau : A5, pages doubles, première page à droite, marges intérieure 12 / extérieure 18 / haut 16 / bas 22 mm, fonds perdus 3 mm ; Guides : ligne de base 13 pt, décalage 16 mm. L'imposition n'est pas faite dans Scribus pour l'imprimeur |
| Affinity Publisher | Nouveau : A5, planches en vis-à-vis, marges 16 / 22 / 12 / 18 mm, fond perdu 3 mm ; grille de ligne de base 13 pt |

Épreuve de bureau : imprimer le PDF en « livret » (imposition automatique
d'Acrobat ou de l'imprimante) sur A4 recto verso, plier, agrafer : c'est la
meilleure vérification du rythme et de la chasse.

## Export

- Intérieur : PDF/X-4 en pages simples dans l'ordre de lecture, fond perdu
  3 mm, traits de coupe. Nombre de pages multiple de 4.
- Couverture : PDF/X-4 de 4 pages simples (C1, C2, C3, C4), ou intégrée à
  l'intérieur en autocouverture (alors un seul PDF : C1, C2, 1 … n, C3, C4).
- Ne jamais livrer un PDF déjà imposé, sauf demande explicite.
- Demander la compensation de la chasse au-delà de 32 pages.
- Nomenclature : `MB_<projet>_livret-a5_interieur_v<nn>_X4.pdf` et
  `MB_<projet>_livret-a5_couverture_v<nn>_X4.pdf`.

## Liste de contrôle

- [ ] Nombre de pages intérieures multiple de 4 ; couverture séparée ou autocouverture décidée avec l'imprimeur.
- [ ] Marges 16 / 22 / 12 / 18 mm ; zone sûre 5 mm (7 mm à l'extérieur des pages centrales au-delà de 48 pages).
- [ ] Corps 10 / 13 pt, 37 lignes par page, images sur la grille de 3 modules.
- [ ] Pleines ouvertures exigeantes placées sur la double page centrale.
- [ ] Folios comptés depuis la première page intérieure, masqués sur la couverture.
- [ ] Épreuve de bureau pliée et agrafée réalisée.
- [ ] Export en pages simples, jamais imposé ; compensation de la chasse demandée si nécessaire.
- [ ] Profil de sortie du devis, PDF/X-4, fond perdu 3 mm, traits de coupe.
