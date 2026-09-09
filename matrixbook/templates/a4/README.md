# Gabarit — A4 portrait

Beau livre, atlas, fonds photographique ou catalogue en A4 (210 × 297 mm),
dos carré collé ou cousu. Deux colonnes de texte, grille de trois modules
pour les images, marges généreuses accueillant les notes marginales et les
légendes en marge.

Grilles SVG associées :
[`grille-a4-page.svg`](../../assets/grids/grille-a4-page.svg) et
[`grille-a4-double-page.svg`](../../assets/grids/grille-a4-double-page.svg)

## Fiche technique

| Paramètre | Valeur |
|-----------|--------|
| Format fini | 210 × 297 mm (portrait) |
| Format avec fond perdu | 216 × 303 mm |
| Fond perdu | 3 mm sur les quatre côtés (5 mm pour la couverture si l'imprimeur le demande) |
| Zone sûre | 6 mm depuis la coupe |
| Marges | Tête 22 mm · Pied 30 mm · Intérieure 20 mm · Extérieure 25 mm |
| Surface de composition | 165 × 245 mm |
| Colonnes | 2 colonnes de 80 mm, gouttière 5 mm (texte) ; grille de 3 modules de 51,67 mm, gouttière 5 mm (images) ; variante « beau livre » : 1 colonne de texte de 80 mm + 1 colonne d'images de 80 mm |
| Grille de ligne de base | 13 pt à partir de la marge de tête ; 53 lignes par page |
| Corps de texte | 10,5 / 13 pt Serif, ≈ 48 caractères par ligne et par colonne |
| Notes | Marginales dans la marge extérieure (largeur utile 19 mm après 6 mm de zone sûre), Sans 8 / 9,75 pt |
| Résolution des images | 300 ppp effectifs ; pleine page à fond perdu ≥ 2 552 × 3 579 px ; pleine ouverture ≥ 5 032 × 3 579 px |
| Espace couleur | CMJN ; PSO Coated v3 (FOGRA51) ou ISO Coated v2 300 % (FOGRA39) selon l'imprimeur |
| Papier conseillé | Intérieur : couché mat ou satiné 150 à 170 g/m² (photographies), couché mat 135 g/m² (texte et images) ; couverture : cartonnée (reliure rigide, carton 2,5 mm habillé) ou souple 350 g/m² pelliculée avec rabats de 100 mm |
| Reliure | Dos carré collé PUR (jusqu'à 160 pages) ; dos cousu collé (au-delà, ou pour une édition de référence) ; reliure rigide cousue pour un beau livre |
| Nombre de pages | Multiple de 4 ; de 64 à 320 pages ; cahiers de 16 (parfois 8 sur papier épais) |

## Schéma de la double page

```text
 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
 ¦ ┌─────────────────────────────────────────┬─────────────────────────────────────────┐ ¦
 ¦ │                 22                      │                      22                 │ ¦
 ¦ │       ┌──────────┬──────────┐           │           ┌──────────┬──────────┐       │ ¦
 ¦ │  25   │    80    │    80    │   20      │     20    │    80    │    80    │   25  │ ¦
 ¦ │       │     5    │          │           │           │          │    5     │       │ ¦
 ¦ │ notes │          │          │           │           │          │          │ notes │ ¦
 ¦ │ marg. │  verso   │          │           │           │          │  recto   │ marg. │ ¦
 ¦ │       │  165 × 245          │           │           │          165 × 245  │       │ ¦
 ¦ │       │          │          │           │           │          │          │       │ ¦
 ¦ │       │  53 lignes de 13 pt │           │           │  53 lignes de 13 pt │       │ ¦
 ¦ │       │          │          │           │           │          │          │       │ ¦
 ¦ │       └──────────┴──────────┘           │           └──────────┴──────────┘       │ ¦
 ¦ │  48                 30                  │                  30                 49  │ ¦
 ¦ └─────────────────────────────────────────┴─────────────────────────────────────────┘ ¦
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                                             ↑ dos
```

Grille d'images à 3 modules superposée aux 2 colonnes de texte :

```text
 ┌────────────────┬────────────────┬────────────────┐   3 modules de 51,67 mm, gouttières 5 mm
 │     module     │     module     │     module     │
 └────────────────┴────────────────┴────────────────┘
 ┌────────────────────────┬─────────────────────────┐   2 colonnes de 80 mm, gouttière 5 mm
 │      colonne texte     │      colonne texte      │
 └────────────────────────┴─────────────────────────┘
   les deux grilles partagent les bords extérieurs (165 mm) ; une image occupe
   1, 2 ou 3 modules, OU une colonne de texte, jamais un mélange des deux
```

## Emprises d'images

| Emprise | Dimensions | Lignes de base | Remarque |
|---------|------------|----------------|----------|
| Pleine ouverture | 426 × 303 mm (avec fond perdu) | — | Sujet hors du pli (10 mm de chaque côté en A4) ; recouvrement de 4 à 6 mm au dos |
| Pleine page à fond perdu | 216 × 303 mm | — | Folio masqué ; légende sur la page en vis-à-vis |
| Pleine page dans les marges | 165 × 245 mm | 53 | Légende en marge extérieure |
| Pleine largeur, 2/3 | 165 × 160 mm | 35 | Composition « asymétrique » |
| Demi-page | 165 × 119,5 mm | 26 | Composition « texte + image » |
| Une colonne | 80 × 60 mm à 80 × 245 mm | 13 à 53 | Variante « beau livre » : colonne d'images en regard du texte |
| 2 modules | 108,33 × 81 mm (4:3) | 18 | — |
| 1 module | 51,67 × 39 mm (4:3) ou 51,67 × 69 mm (3:4) | 8 ou 15 | Vignette, mosaïque |

## Variante « beau livre »

Pour un fonds photographique où l'image domine (ratio 25 / 75) : la colonne
de gauche de chaque page porte le texte (80 mm, ≈ 48 caractères), la colonne
de droite les images et leurs légendes, ou l'inverse en miroir sur le verso
(texte côté dos, images côté extérieur). Les légendes se placent alors dans
la colonne d'images, sous chaque image, ou dans la marge extérieure en
`MB-P/Note marginale` pour les images pleine page.

## Structure type (160 pages)

| Pages | Contenu |
|-------|---------|
| C1–C4 | Couverture (rigide : plats + dos ; souple : à plat avec rabats) |
| 1–7 | Liminaires : faux-titre, frontispice, titre, mentions, sommaire, blanche, avant-propos |
| 8–9 | Carte de situation en double page |
| 10–11 | Ouverture du chapitre 1 |
| 12–147 | Corps : 6 à 8 chapitres de 16 à 24 pages ; une pleine ouverture par chapitre au moins |
| 148–153 | Chronologie et cartes de synthèse |
| 154–157 | Index des lieux et des personnes (2 colonnes) |
| 158–159 | Sources, crédits, remerciements |
| 160 | Achevé d'imprimer |

## Configuration du document

| Logiciel | Réglages |
|----------|----------|
| InDesign | Nouveau document : A4, pages en vis-à-vis, marges tête 22 / pied 30 / intérieure 20 / extérieure 25 mm, colonnes 2 / gouttière 5 mm, fond perdu 3 mm ; grille de ligne de base 13 pt, début à 22 mm par rapport à la marge ; gabarit « Images » avec 3 colonnes / gouttière 5 mm |
| Scribus | Fichier › Nouveau : A4, portrait, pages doubles, première page à droite, marges intérieure 20 / extérieure 25 / haut 22 / bas 30 mm, fonds perdus 3 mm ; Guides : ligne de base 13 pt, décalage 22 mm ; repères de colonnes 2 / 5 mm et, sur un calque de guides séparé, 3 / 5 mm |
| Affinity Publisher | Nouveau : A4, planches en vis-à-vis, marges 22 / 30 / 20 / 25 mm, fond perdu 3 mm ; grille de ligne de base 13 pt ; guides de colonnes 2 / 5 mm |

## Couverture

- **Souple** : document à plat, largeur = 210 + dos + 210 mm (+ rabats),
  hauteur 297 mm, fond perdu 3 à 5 mm selon l'imprimeur.
- **Rigide (cartonnée)** : l'imprimeur fournit un gabarit avec les
  débords de rembordage (généralement 15 à 20 mm autour), l'épaisseur des
  cartons et les mors ; on compose dans ce gabarit. Le format fini d'un livre
  rigide dépasse le bloc intérieur de 3 à 4 mm en tête, pied et gouttière
  extérieure (« chasse » de la couverture) : ne pas confondre avec le fond
  perdu.
- Le titre du dos se lit de haut en bas ; le code-barres en C4 dans la zone
  sûre, noir sur blanc.

## Export

- Intérieur : PDF/X-4 en pages simples, fond perdu 3 mm, traits de coupe,
  profil du devis.
- Couverture : PDF/X-4 d'une page à plat (souple) ou dans le gabarit de
  l'imprimeur (rigide).
- Pour les pleines ouvertures, vérifier avec l'imprimeur s'il préfère un
  recouvrement prévu dans la maquette ou une image continue livrée à part.
- Nomenclature : `MB_<projet>_livre-a4_interieur_v<nn>_X4.pdf` et
  `MB_<projet>_livre-a4_couverture_v<nn>_X4.pdf`.

## Liste de contrôle

- [ ] Marges 22 / 30 / 20 / 25 mm, zone sûre 6 mm, pages en vis-à-vis.
- [ ] Deux colonnes de 80 mm pour le texte ; aucune ligne de plus de 55 caractères.
- [ ] Corps 10,5 / 13 pt sur grille 13 pt ; 53 lignes par page.
- [ ] Images sur les 3 modules ou sur une colonne de texte, jamais entre les deux grilles.
- [ ] Pleines ouvertures vérifiées au pli (10 mm) avec recouvrement de 4 à 6 mm.
- [ ] Notes marginales dans la marge extérieure, à 6 mm minimum de la coupe.
- [ ] Nombre de pages multiple de 16 en offset ; épaisseur du dos validée sur maquette en blanc.
- [ ] Profil de sortie confirmé (FOGRA51 ou FOGRA39) ; épreuve contractuelle sur les pages photographiques critiques.
