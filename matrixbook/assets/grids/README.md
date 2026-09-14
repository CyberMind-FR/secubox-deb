# Grilles

Grilles SVG à l'échelle réelle (1 unité SVG = 1 mm) pour chaque gabarit
MatrixBook. Elles se superposent à une page ou une double page dans un logiciel
de mise en page, un navigateur ou un outil vectoriel, pour contrôler visuellement
le fond perdu, la zone sûre, les marges, les colonnes et la ligne de base.

Les grilles sont générées par script à partir des valeurs des gabarits : si une
valeur change dans un README de `templates/`, la grille correspondante doit être
régénérée pour rester la source de vérité visuelle.

## Fichiers

| Fichier | Format | Contenu | Gabarit |
|---------|--------|---------|---------|
| `grille-carte-postale-148x105.svg` | 154 × 111 mm (avec fond perdu) | Recto d'une carte postale, 2 colonnes | [postcard](../../templates/postcard/README.md) |
| `grille-a5-page.svg` | 154 × 216 mm | Page simple A5, 1 colonne | [a5](../../templates/a5/README.md) |
| `grille-a5-double-page.svg` | 302 × 216 mm | Double page A5 avec pli | [a5](../../templates/a5/README.md) |
| `grille-a4-page.svg` | 216 × 303 mm | Page simple A4, 2 colonnes | [a4](../../templates/a4/README.md) |
| `grille-a4-double-page.svg` | 426 × 303 mm | Double page A4 avec pli | [a4](../../templates/a4/README.md) |
| `grille-livret-a5-double-page.svg` | 302 × 216 mm | Double page de livret agrafé, marge intérieure réduite | [booklet](../../templates/booklet/README.md) |

## Code couleur

| Couleur | Trait | Signification |
|---------|-------|---------------|
| Rouge pointillé | Contour extérieur | Limite du fond perdu (3 mm au-delà du format fini) |
| Noir continu | Rectangle | Format fini (ligne de coupe), avec traits de coupe aux angles |
| Vert pointillé | Rectangle intérieur | Zone sûre : aucun texte ni élément important au-delà |
| Bleu continu | Rectangle | Bloc de marges (zone de composition) |
| Bleu translucide | Bandes | Colonnes de texte, séparées par les gouttières |
| Gris fin | Lignes horizontales | Grille de ligne de base à 13 pt (4,586 mm) |
| Ocre pointillé | Verticale centrale | Pli d'une double page |

## Utilisation

### Dans InDesign ou Affinity Publisher

1. Créez le document aux dimensions du gabarit **avec** le fond perdu (les
   SVG incluent déjà 3 mm de chaque côté).
2. Importez le SVG sur un calque `Grille` verrouillé et non imprimable
   (« Fichier › Importer », puis dans les options de calque décochez « Imprimer »).
3. Alignez l'angle supérieur gauche du SVG sur l'angle supérieur gauche du
   fond perdu (coordonnées −3 mm ; −3 mm par rapport à la page).

### Dans Scribus

1. « Fichier › Importer › Image vectorielle », choisissez le SVG.
2. Positionnez-le à X = −3 mm, Y = −3 mm (propriétés de l'objet).
3. Placez-le sur un calque non imprimable et verrouillez-le.

### Dans un navigateur

Ouvrez le fichier directement : les dimensions en millimètres sont respectées à
l'affichage 100 % et à l'impression, ce qui permet d'imprimer la grille sur du
papier pour des maquettes en blanc.

## Régénérer les grilles

Les grilles ont été produites avec un script Python sans dépendance externe
qui prend en entrée les valeurs des gabarits. Pour une variante (autre format,
autres marges), reprenez la même logique : dessinez dans l'ordre le fond perdu,
le format fini, la zone sûre, le bloc de marges, les colonnes, puis la ligne de
base, en millimètres. Le fichier doit rester lisible et documenté dans sa balise
`<desc>`.
