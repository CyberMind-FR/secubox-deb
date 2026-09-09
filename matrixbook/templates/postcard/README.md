# Gabarit — Carte postale 148 × 105 mm

Carte postale au format A6 paysage, le standard des cartes anciennes et des
séries patrimoniales. Recto : image et titre court ; verso : légende complète,
source, correspondance, adresse et timbre.

Grille SVG associée : [`assets/grids/grille-carte-postale-148x105.svg`](../../assets/grids/grille-carte-postale-148x105.svg)

## Fiche technique

| Paramètre | Valeur |
|-----------|--------|
| Format fini | 148 × 105 mm (paysage) |
| Format avec fond perdu | 154 × 111 mm |
| Fond perdu | 3 mm sur les quatre côtés |
| Zone sûre | 5 mm depuis la coupe (138 × 95 mm utiles) |
| Marges (verso) | 8 mm sur les quatre côtés |
| Surface de composition (verso) | 132 × 89 mm |
| Colonnes (verso) | 2 colonnes de 64 mm, gouttière 4 mm |
| Grille de ligne de base | 13 pt à partir de la marge de tête (19 lignes) |
| Résolution des images | 300 ppp effectifs (image recto ≥ 1 820 × 1 312 px pour le fond perdu) ; 1 200 ppp pour un document au trait |
| Espace couleur | CMJN, profil ISO Coated v2 300 % (FOGRA39) par défaut |
| Papier conseillé | Couché mat 350 g/m² ; ou carte non couchée 300 g/m² (profil FOGRA52) pour un rendu « ancien » et l'écriture au stylo ; vernis ou pelliculage mat au recto en option |
| Reliure | Aucune ; coins droits (les coins arrondis sont hors design system) |
| Orientation | Paysage au recto et au verso, même sens de lecture |
| Nombre de pages | 2 (recto, verso) |

## Recto

```text
 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐  fond perdu 154 × 111
 ¦ ┌───────────────────────────────────────────────────┐ ¦  coupe 148 × 105
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ image à fond perdu ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓ ┌──────────────────────────┐ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ │▓▓ │ ⌖ LE CRUET · VERS 1912   │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦  cartouche à 8 mm des bords
 ¦ │▓▓ └──────────────────────────┘ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ ¦
 ¦ └───────────────────────────────────────────────────┘ ¦
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

- **Image** : une seule, à fond perdu sur les quatre côtés, recadrée pour
  que le sujet soit à plus de 8 mm des bords. Pour une carte postale
  ancienne reproduite « en fac-similé » (avec ses bords), on la centre dans
  un fond `MB-Parchemin` ou `MB-Noir riche` à fond perdu, à 6 mm minimum de
  la coupe, avec un filet 0,25 pt `MB-Gris pierre`.
- **Cartouche** : lieu et date, style `MB-P/Cartouche`, fond `MB-Parchemin`
  ou accent 100 %, posé dans une zone homogène à 8 mm des bords (dans la zone
  sûre). Toujours au même angle sur toute la série (angle inférieur gauche
  par défaut).
- **Titre** (facultatif) : `MB-P/H1` variante carte postale, Sans SemiBold
  14 pt, en réserve ou en noir selon le fond, dans la zone sûre. Pas de
  sous-titre au recto.

## Verso

```text
 ┌───────────────────────────────────────────────────────┐ coupe 148 × 105
 │ 8                                                     │
 │   ┌──────────────────────────┐ ┌────────────────────┐ │
 │   │ Sujet de la carte.       │ │           ┌──────┐ │ │  rectangle timbre
 │   │ Lieu, date. Commentaire. │ │           │      │ │ │  22 × 26 mm, filet
 │   │ Source, coll., cote.     │ │           │      │ │ │  0,25 pt, à 5 mm
 │   │                          │ │           └──────┘ │ │  des bords de coupe
 │   │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │ │                    │ │
 │   │                          │ │  ──────────────    │ │  lignes d'adresse
 │   │   zone de                │ │  ──────────────    │ │  0,25 pt gris brume
 │   │   correspondance         │ │  ──────────────    │ │  espacées de 13 pt
 │   │   (vide)                 │ │  ──────────────    │ │
 │   │                          │ │                    │ │
 │   │ Éditeur · série 3/12     │ │  ▌▌▌ code-barres   │ │
 │   └──────────────────────────┘ └────────────────────┘ │
 │ 8          64            4            64          8   │
 └───────────────────────────────────────────────────────┘
        ↑ colonne gauche              ↑ colonne droite
```

| Zone | Position | Composition |
|------|----------|-------------|
| Légende | Haut de la colonne gauche, 3 à 6 lignes | `MB-P/Légende` en 7,5 / 9,75 pt : sujet en SemiBold, lieu et date, commentaire, source en italique. 250 à 400 signes |
| Séparateur | Sous la légende | Filet 0,25 pt `MB-Gris brume` sur la largeur de la colonne, ou une ligne de base vide |
| Correspondance | Reste de la colonne gauche | Vide ; fond papier ou `MB-Parchemin` très léger (ne pas gêner l'écriture) |
| Mention éditeur et série | Dernière ligne de la colonne gauche | `MB-P/Cartouche` sans fond, 7,5 pt : nom de l'éditeur ou de l'association, numéro de série « 3/12 », année |
| Rectangle du timbre | Angle supérieur droit, 22 × 26 mm, à 5 mm des bords de coupe (donc à cheval sur la marge) | Filet 0,25 pt `MB-Gris pierre`, coins droits ; texte « Timbre » facultatif en 6 pt gris |
| Lignes d'adresse | Colonne droite, 4 lignes | Filets 0,25 pt `MB-Gris brume`, largeur 64 mm, espacées de 13 pt (une ligne de base), première ligne à 26 pt sous le rectangle du timbre |
| Code-barres, prix, mention légale | Bas de la colonne droite | Code-barres EAN dans la zone sûre (largeur ≥ 30 mm, noir 100 K, fond blanc) ; mentions en 6 pt `MB-Gris pierre` (limite basse absolue) |
| Séparation des colonnes | Gouttière centrale | Une ligne verticale 0,25 pt `MB-Gris brume` est admise ici, par tradition postale (seule exception à la règle « pas de filet vertical ») |

Le verso est composé sur le fond du papier ; si un fond `MB-Parchemin` est
utilisé, il est à fond perdu et le rectangle du timbre reste blanc.

## Configuration du document

| Logiciel | Réglages |
|----------|----------|
| InDesign | Nouveau document : 148 × 105 mm, orientation paysage, 2 pages, pages en vis-à-vis décoché, marges 8 mm, colonnes 2 / gouttière 4 mm, fond perdu 3 mm ; grille de ligne de base 13 pt, début à 8 mm (marge) |
| Scribus | Fichier › Nouveau : Personnalisé 148 × 105 mm, paysage, page simple, 2 pages, marges 8 mm, fonds perdus 3 mm ; Réglages du document › Guides : ligne de base 13 pt, décalage 8 mm ; colonnes définies dans le cadre de texte (2, gouttière 4 mm) |
| Affinity Publisher | Nouveau : 148 × 105 mm, planches désactivées, 2 pages, marges 8 mm, fond perdu 3 mm ; grille de ligne de base 13 pt |

## Série de cartes

Une série patrimoniale (6, 12 ou 24 cartes) partage : la même image de fond
de verso, le même cartouche au même angle, la même mention éditeur, une
numérotation « n/N ». Les images recto sont choisies à emprise identique
(fond perdu total) ou toutes en fac-similé, jamais en mélange. Le chemin de
fer d'une série est une simple liste ordonnée : numéro, image, légende.

## Export

- Un PDF/X-4 de 2 pages (recto puis verso), fond perdu 3 mm, traits de coupe,
  profil du devis ; ou deux PDF distincts si demandé.
- Pour une série : un PDF par carte, nommé
  `MB_<projet>_carte-postale_<nn>_v<version>_X4.pdf`, ou un PDF multipage
  dans l'ordre (recto 1, verso 1, recto 2, verso 2…) selon l'imprimeur.
- Vérifier l'orientation identique des deux faces et la position du
  rectangle du timbre dans la zone sûre.

## Liste de contrôle

- [ ] Image recto à fond perdu, sujet à plus de 8 mm des bords, ≥ 300 ppp effectifs.
- [ ] Cartouche dans la zone sûre, au même angle que le reste de la série.
- [ ] Légende complète (sujet, lieu, date, commentaire, source) au verso, ≥ 7,5 pt.
- [ ] Rectangle du timbre 22 × 26 mm, à 5 mm des bords de coupe.
- [ ] Lignes d'adresse sur la grille, colonne droite.
- [ ] Mention éditeur, numéro de série, code-barres si vente.
- [ ] Aucun texte sous 6 pt ; aucun texte hors zone sûre.
- [ ] Export PDF/X-4, 2 pages, fond perdu 3 mm, profil du devis.
