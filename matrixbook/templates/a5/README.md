# Gabarit — A5 portrait

Livre A5 (148 × 210 mm) en dos carré collé : chronique, recueil, monographie,
catalogue d'exposition. Une colonne de texte, images sur une grille de trois
modules. C'est le gabarit de référence dont dérivent les autres.

Grilles SVG associées :
[`grille-a5-page.svg`](../../assets/grids/grille-a5-page.svg) et
[`grille-a5-double-page.svg`](../../assets/grids/grille-a5-double-page.svg)

## Fiche technique

| Paramètre | Valeur |
|-----------|--------|
| Format fini | 148 × 210 mm (portrait) |
| Format avec fond perdu | 154 × 216 mm |
| Fond perdu | 3 mm sur les quatre côtés |
| Zone sûre | 5 mm depuis la coupe |
| Marges | Tête 16 mm · Pied 22 mm · Intérieure 14 mm · Extérieure 18 mm |
| Surface de composition | 116 × 172 mm |
| Colonnes | 1 colonne de 116 mm (texte) ; grille de 3 modules de 36 mm, gouttière 4 mm (images) ; 2 colonnes de 56 mm pour les pages finales |
| Grille de ligne de base | 13 pt à partir de la marge de tête ; 37 lignes par page |
| Corps de texte | 10 / 13 pt Serif, ≈ 70 caractères par ligne |
| Résolution des images | 300 ppp effectifs ; pleine page à fond perdu ≥ 1 820 × 2 552 px ; pleine ouverture ≥ 3 570 × 2 552 px |
| Espace couleur | CMJN ; PSO Uncoated v3 (FOGRA52) sur bouffant, ISO Coated v2 300 % (FOGRA39) sur couché |
| Papier conseillé | Intérieur : bouffant non couché 90 g/m² (lecture, texte dominant) ou couché mat 115 à 135 g/m² (images dominantes) ; couverture : 300 g/m² couché mat, pelliculage mat, rabats de 80 mm en option |
| Reliure | Dos carré collé (PUR de préférence, tient mieux l'ouverture) ; dos cousu collé au-delà de 200 pages ou pour une édition durable |
| Nombre de pages | Multiple de 4 ; de 48 à 240 pages ; cahiers de 16 en offset |
| Épaisseur du dos | Fournie par l'imprimeur ; ordre de grandeur : pages ÷ 2 × épaisseur d'une feuille (90 g/m² bouffant ≈ 0,12 mm → 96 pages ≈ 5,8 mm) |

## Schéma de la double page

```text
 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
 ¦ ┌───────────────────────────────────┬───────────────────────────────────┐ ¦
 ¦ │              16                   │                  16               │ ¦
 ¦ │      ┌────┬────┬────┐             │             ┌────┬────┬────┐      │ ¦
 ¦ │  18  │ 36 │ 36 │ 36 │   14        │      14     │ 36 │ 36 │ 36 │  18  │ ¦
 ¦ │      │    4    4    │             │             │    4    4    │      │ ¦
 ¦ │      │              │             │             │              │      │ ¦
 ¦ │      │   verso      │             │             │    recto     │      │ ¦
 ¦ │      │   116 × 172  │             │             │   116 × 172  │      │ ¦
 ¦ │      │              │             │             │              │      │ ¦
 ¦ │      │   37 lignes  │             │             │   37 lignes  │      │ ¦
 ¦ │      │   de 13 pt   │             │             │   de 13 pt   │      │ ¦
 ¦ │      │              │             │             │              │      │ ¦
 ¦ │      └──────────────┘             │             └──────────────┘      │ ¦
 ¦ │  24                 22            │            22                 25  │ ¦
 ¦ └───────────────────────────────────┴───────────────────────────────────┘ ¦
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                                       ↑ dos
```

## Emprises d'images

| Emprise | Dimensions | Lignes de base | Remarque |
|---------|------------|----------------|----------|
| Pleine ouverture | 302 × 216 mm (avec fond perdu) | — | Sujet hors du pli (8 mm de chaque côté) ; recouvrement de 3 à 5 mm au dos |
| Pleine page à fond perdu | 154 × 216 mm | — | Folio masqué |
| Pleine page dans les marges | 116 × 172 mm | 37 | Légende en marge de pied ou sur la page en vis-à-vis |
| Pleine largeur, 2/3 de hauteur | 116 × 110 mm | 24 | Composition « asymétrique » |
| Demi-page | 116 × 82,5 mm | 18 | Composition « texte + image » |
| 2 modules | 76 × 55 mm (paysage 4:3) ou 76 × 101 mm (portrait) | 12 ou 22 | — |
| 1 module | 36 × 27 mm à 36 × 50 mm | 6 à 11 | Vignette, mosaïque |

Les hauteurs sont arrondies au nombre entier de lignes de base (4,586 mm)
pour que la légende retombe sur la grille.

## Structure type (96 pages)

| Pages | Contenu |
|-------|---------|
| C1–C4 | Couverture à plat (C4 + dos + C1), C2 et C3 blanches ou teintées |
| 1 | Faux-titre |
| 2 | Frontispice ou blanche |
| 3 | Page de titre |
| 4 | Mentions légales, ISBN, crédits |
| 5 | Sommaire |
| 6–7 | Avant-propos |
| 8–9 | Ouverture du chapitre 1 (double page) |
| 10–85 | Corps : 5 à 6 chapitres de 12 à 16 pages, une respiration toutes les 3 doubles pages au plus |
| 86–89 | Chronologie, glossaire |
| 90–93 | Sources, bibliographie, crédits photographiques détaillés |
| 94 | Remerciements |
| 95 | Table des matières détaillée ou blanche |
| 96 | Achevé d'imprimer |

## Configuration du document

| Logiciel | Réglages |
|----------|----------|
| InDesign | Nouveau document : 148 × 210 mm, pages en vis-à-vis, nombre de pages, marges tête 16 / pied 22 / intérieure 14 / extérieure 18 mm, colonnes 1, fond perdu 3 mm ; grille de ligne de base 13 pt, début à 16 mm par rapport à la marge ; grille de mise en page 3 colonnes / gouttière 4 mm sur un gabarit « Images » (« Page › Marges et colonnes ») |
| Scribus | Fichier › Nouveau : A5, portrait, pages doubles (« Pages en regard »), première page à droite, marges intérieure 14 / extérieure 18 / haut 16 / bas 22 mm, fonds perdus 3 mm ; Guides : ligne de base 13 pt, décalage 16 mm ; guides de colonnes « Page › Gérer les repères › Colonnes / lignes » : 3 colonnes, gouttière 4 mm |
| Affinity Publisher | Nouveau : A5, planches en vis-à-vis, marges 16 / 22 / 14 / 18 mm, fond perdu 3 mm ; grille de ligne de base 13 pt ; guides de colonnes 3 / 4 mm |

## Couverture

Document séparé, à plat : largeur = 148 + dos + 148 mm (+ 2 × 80 mm de
rabats si prévus), hauteur 210 mm, fond perdu 3 mm. Le titre du dos se lit de
haut en bas, en `MB-P/H5` ou `MB-P/Cartouche`, centré sur l'épaisseur ; si le
dos fait moins de 5 mm, il reste vierge. Le code-barres EAN (ISBN) est en C4,
angle inférieur, dans la zone sûre, noir sur blanc, largeur ≥ 30 mm. Le prix et
la mention de l'éditeur figurent en C4.

## Export

- Intérieur : un PDF/X-4 en pages simples, fond perdu 3 mm, traits de coupe.
- Couverture : un PDF/X-4 d'une page à plat, avec l'épaisseur de dos validée
  sur une maquette en blanc.
- Nomenclature : `MB_<projet>_livre-a5_interieur_v<nn>_X4.pdf` et
  `MB_<projet>_livre-a5_couverture_v<nn>_X4.pdf`.

## Liste de contrôle

- [ ] Marges 16 / 22 / 14 / 18 mm, pages en vis-à-vis, page 1 en recto.
- [ ] Nombre de pages multiple de 4 (idéalement de 16), au moins 48.
- [ ] Corps 10 / 13 pt sur grille 13 pt ; 37 lignes par page.
- [ ] Images sur 1, 2 ou 3 modules, ou pleine largeur, ou fond perdu ; hauteurs en lignes de base.
- [ ] Pleines ouvertures vérifiées au pli avec recouvrement.
- [ ] Folios en pied, extérieur, masqués sur liminaires et planches à fond perdu.
- [ ] Profil de sortie adapté au papier (FOGRA52 bouffant, FOGRA39 couché).
- [ ] Couverture à plat avec l'épaisseur de dos fournie par l'imprimeur.
