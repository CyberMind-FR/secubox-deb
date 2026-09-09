# Typographie

Ce guide définit le système typographique MatrixBook : familles, échelle des
titres, corps de texte, citations, notes, légendes, espacements et grille de
ligne de base. Il s'applique à tous les gabarits ; seules quelques valeurs
changent d'un format à l'autre (voir le tableau final).

## Sommaire

1. [Principes](#1-principes)
2. [Familles de caractères](#2-familles-de-caractères)
3. [Échelle des titres H1 à H6](#3-échelle-des-titres-h1-à-h6)
4. [Corps de texte](#4-corps-de-texte)
5. [Citations](#5-citations)
6. [Légendes](#6-légendes)
7. [Notes](#7-notes)
8. [Éléments de navigation](#8-éléments-de-navigation)
9. [Espacements](#9-espacements)
10. [Grille typographique](#10-grille-typographique)
11. [Conventions typographiques françaises](#11-conventions-typographiques-françaises)
12. [Valeurs par gabarit](#12-valeurs-par-gabarit)

## 1. Principes

- **Deux familles, pas plus.** Une serif pour le texte lu (corps, titres,
  citations), une sans-serif pour le texte consulté (légendes, cartouches,
  tableaux, folios, notes marginales). Ce partage sémantique rend la
  hiérarchie lisible sans couleur.
- **Une ligne de base unique.** Tout s'aligne sur une grille de 13 pt. Un
  style dont l'interlignage n'est pas 13 pt ou un multiple occupe un nombre
  entier de lignes de base grâce à ses espaces avant et après.
- **Une échelle fermée.** Les corps sont choisis parmi une liste fixe. Il n'y
  a pas de « 10,7 pt pour faire rentrer ».
- **La lisibilité prime sur l'expressivité.** Les publications MatrixBook
  sont lues par un public large, souvent âgé ; le corps minimal du texte
  courant est de 10 pt et celui de toute information de 7,5 pt.

## 2. Familles de caractères

| Rôle | Famille recommandée | Licence | Alternatives compatibles |
|------|---------------------|---------|--------------------------|
| Serif (texte lu) | EB Garamond | SIL Open Font License | Libertinus Serif, Crimson Pro, Source Serif 4 |
| Sans-serif (texte consulté) | Source Sans 3 | SIL Open Font License | IBM Plex Sans, Fira Sans, Inter |

Ces familles sont libres, disponibles en OpenType complet (petites capitales,
chiffres elzéviriens et tabulaires, ligatures, accents français) et existent en
graisses suffisantes (Regular, Italic, Medium, SemiBold, Bold).

Graisses autorisées :

- Serif : Regular, Italic, Medium, SemiBold. Jamais de Bold dans le corps,
  jamais de Light.
- Sans : Regular, Italic, SemiBold. Le Bold est réservé aux cartouches de
  couverture.

Fonctions OpenType à activer par défaut dans les styles :

| Fonction | Serif (corps) | Sans (légendes, tableaux) |
|----------|---------------|---------------------------|
| Ligatures standard (fi, fl, ffi) | Oui | Oui |
| Chiffres elzéviriens (minuscules) | Oui, dans le texte courant | Non |
| Chiffres tabulaires alignés | Non, sauf tableaux | Oui |
| Petites capitales | Oui, pour H4 et sigles | Oui, pour H5, H6 |
| Crénage optique | Oui (InDesign) ou métrique | Métrique |

## 3. Échelle des titres H1 à H6

L'échelle suit un ratio proche de la tierce majeure (1,25) puis est arrondie
pour que chaque bloc de titre occupe un nombre entier de lignes de 13 pt.

| Niveau | Usage | Famille, graisse | Corps / interlignage | Casse | Espace avant / après | Lignes occupées |
|--------|-------|------------------|----------------------|-------|----------------------|-----------------|
| H1 | Titre de chapitre | Serif Regular | 30 / 39 pt | Bas de casse, capitale initiale | 0 / 26 pt | 3 + 2 |
| H2 | Section | Serif Medium | 18 / 26 pt | Bas de casse | 26 / 13 pt | 2 + 1 + 2 |
| H3 | Sous-section | Serif SemiBold | 13 / 13 pt | Bas de casse | 13 / 0 pt | 1 + 1 |
| H4 | Intertitre | Serif Regular | 10 / 13 pt | Petites capitales, approche +40 | 13 / 0 pt | 1 + 1 |
| H5 | Titre de bloc (encadré, tableau) | Sans SemiBold | 9 / 13 pt | Capitales, approche +60 | 0 / 0 pt | 1 |
| H6 | Étiquette (cartouche, sur-titre) | Sans Regular | 7,5 / 13 pt | Capitales, approche +80 | 0 / 0 pt | 1 |

Règles :

- **H1** n'apparaît qu'en ouverture de chapitre, une fois par chapitre,
  toujours sur une double page. Sur la couverture, le titre du livre utilise
  un style « H1 couverture » dérivé (corps 36 à 48 pt selon le format), seul
  cas de corps libre.
- **H2** ouvre une section dans le corps du chapitre ; deux H2 ne se suivent
  jamais sans texte entre eux.
- **H3** et **H4** sont « collés » au paragraphe qui suit (option « ne pas
  séparer des lignes suivantes »).
- **H5** et **H6** ne portent jamais de ponctuation finale.
- Aucun titre n'est justifié, aucun ne se coupe par césure, aucun n'est
  souligné.
- Un titre en fin de page sans au moins deux lignes de texte sous lui passe
  à la page suivante.

Numérotation : les chapitres sont numérotés en chiffres arabes dans le
chemin de fer ; à l'impression, le numéro est porté par un H6 au-dessus du H1
(« Chapitre 2 ») ou omis. Les sections ne sont pas numérotées dans un livre
illustré.

## 4. Corps de texte

| Paramètre | Valeur |
|-----------|--------|
| Style | Serif Regular |
| Corps / interlignage | 10 / 13 pt (A5, livret) — 10,5 / 13 pt (A4) |
| Justification | Justifié, dernière ligne à gauche |
| Retrait de première ligne | 4 mm, sauf le premier paragraphe après un titre, un blanc ou une image |
| Espace entre paragraphes | 0 pt (le retrait marque le paragraphe) |
| Approche | 0 |
| Espace-mot | Minimum 85 %, optimal 100 %, maximum 125 % |
| Espace-lettre | Minimum −2 %, optimal 0 %, maximum +2 % |
| Glyphes | 100 % (pas de mise à l'échelle) |
| Césure | Activée, 3 lettres avant et après la coupure, 2 coupures consécutives maximum, mots capitalisés non coupés, dernier mot de paragraphe non coupé |
| Veuves et orphelines | 2 lignes minimum en début et en fin de page ou de colonne |
| Longueur de ligne | 55 à 75 caractères (A5, une colonne : ≈ 70 ; A4, deux colonnes : ≈ 48) |

Le **chapeau** (paragraphe d'introduction d'un chapitre) est composé en Serif
Italic 11 / 13 pt, sans retrait, ferré à gauche, sur la largeur du texte
courant, suivi d'un espace après de 13 pt. Il ne dépasse pas 600 signes.

Le **paragraphe de transition** (fin de chapitre, envoi) peut être composé en
retrait de 8 mm à gauche et à droite, dans le même style que le corps.

Le texte courant en **deux colonnes** (A4, pages finales) garde 10 / 13 pt ;
les colonnes sont équilibrées sur la dernière page de section.

## 5. Citations

Trois niveaux de citation coexistent :

| Type | Longueur | Composition |
|------|----------|-------------|
| Citation courte | Moins de 3 lignes | Dans le texte courant, entre guillemets « français », en romain (l'italique est réservé aux titres d'œuvres et aux mots étrangers) |
| Citation en bloc | 3 lignes et plus | Paragraphe détaché, Serif Italic 10 / 13 pt, retrait de 8 mm à gauche et à droite, ferré à gauche, espace avant 13 pt et après 13 pt, sans guillemets. La source suit, en Sans Regular 8 / 13 pt, alignée à droite du bloc, précédée d'un tiret cadratin |
| Exergue | 1 à 4 lignes | Serif Italic 16 / 26 pt, centré ou ferré à gauche sur la moitié de la largeur, espace avant 26 pt et après 26 pt. Réservé aux respirations et ouvertures. Source en Sans Regular 8 / 13 pt sous l'exergue |

Le **témoignage oral** (collecté en entretien) est traité comme une citation en
bloc, avec l'icône `temoin` du jeu d'icônes et une source du type « Marie D.,
née en 1934, entretien du 12 mars 2025 ».

Les coupures dans une citation sont signalées par des crochets « […] » ; les
ajouts de l'auteur par des crochets aussi. L'orthographe d'un document ancien
est respectée et, si nécessaire, suivie de « [sic] ».

## 6. Légendes

| Paramètre | Valeur |
|-----------|--------|
| Style | Sans Regular |
| Corps / interlignage | 8 / 9,75 pt (4 lignes de légende = 3 lignes de base) |
| Alignement | Ferré à gauche, sans césure |
| Largeur | Largeur de l'image, ou une colonne, ou la marge extérieure |
| Sujet de la légende | Sans SemiBold, même corps |
| Source | Sans Italic, même corps |
| Distance à l'image | 2 mm (sous l'image) ; alignée sur le bord gauche de l'image |
| Longueur | Voir la méthodologie, section [Légendes](MATRIXBOOK_DESIGN.md#6-légendes) |

Les légendes de mosaïque sont numérotées avec des chiffres tabulaires suivis
d'un point et d'une espace insécable : « 1. La mairie… ». Le numéro peut être
reporté sur l'image dans un cartouche de 4 mm (voir
[DESIGN_SYSTEM.md](DESIGN_SYSTEM.md#5-cartouches)).

Sur une image sombre en pleine ouverture, la légende en réserve est composée en
blanc (papier), Sans Regular 8 / 9,75 pt, avec un contraste vérifié ; elle
n'est jamais posée sur un motif.

## 7. Notes

Le livre illustré limite les notes ; elles sont réservées aux références de
sources et aux précisions qui alourdiraient le texte.

| Type | Composition | Appel |
|------|-------------|-------|
| Note de bas de page | Serif Regular 7,5 / 9,75 pt, ferrée à gauche, séparée du texte par un filet de 0,25 pt sur 20 mm et un espace de 13 pt | Chiffre arabe en exposant, numérotation continue par chapitre |
| Note marginale (A4) | Sans Regular 7,5 / 9,75 pt, dans la marge extérieure, alignée sur la ligne de l'appel | Chiffre arabe en exposant |
| Note de l'éditeur | Idem note de bas de page, précédée de « N.D.É. » | Astérisque |
| Notes en fin de volume | Serif Regular 8 / 9,75 pt en deux colonnes, regroupées par chapitre | Chiffre arabe en exposant |

L'**appel de note** se place en exposant, collé au mot qu'il complète, avant
la ponctuation (« …la scierie¹. »), sauf après un point d'interrogation ou
d'exclamation où il suit. Il n'y a jamais d'appel de note dans un titre ni
dans une légende (la source y est écrite en clair).

Le bloc de notes est ancré en bas de la page, dans la surface de composition ;
il n'empiète pas sur la marge inférieure.

## 8. Éléments de navigation

| Élément | Composition | Position |
|---------|-------------|----------|
| Folio (numéro de page) | Sans Regular 8 / 13 pt, chiffres tabulaires | Bas de page, aligné sur la marge extérieure, sur la première ligne sous la surface de composition |
| Titre courant | Sans Regular 7,5 pt, petites capitales, approche +50 | Même ligne que le folio, aligné sur la marge intérieure ; verso : titre du livre, recto : titre du chapitre |
| Renvoi de page | Dans le texte : « (voir p. 24) » ; en légende : icône `fleche` + « p. 24 » | — |
| Sommaire | Serif Regular 10 / 13 pt, folios en chiffres tabulaires alignés à droite avec points de conduite espacés | Page 5 (ou page 3 d'un livret) |
| Index, glossaire | Serif Regular 8,5 / 9,75 pt, deux colonnes, entrées en Sans SemiBold | Pages finales |

Le folio et le titre courant sont masqués sur : la couverture, les pages
liminaires jusqu'au sommaire inclus, les pleines ouvertures, les pleines pages
à fond perdu, les pages blanches.

## 9. Espacements

Toutes les valeurs verticales sont des multiples de la ligne de base (13 pt).
Les valeurs horizontales sont en millimètres, sur le module de 4 mm de la grille.

| Espacement | Valeur | Remarque |
|------------|--------|----------|
| Ligne de base | 13 pt = 4,586 mm | Pas de la grille |
| Retrait de paragraphe | 4 mm | 1 module |
| Retrait de citation en bloc | 8 mm | 2 modules |
| Entre un titre H2 et le texte | 13 pt | 1 ligne |
| Entre le texte et une image | 13 pt au-dessus, 13 pt + légende au-dessous | L'image est calée sur la ligne de base par son bord supérieur |
| Entre l'image et sa légende | 2 mm | Puis la légende occupe un multiple de 3 lignes de base par blocs de 4 lignes |
| Entre deux images d'une mosaïque | 4 mm | 1 module = gouttière |
| Marge intérieure d'un encadré | 4 mm | Texte de l'encadré sur la grille |
| Après un chapeau | 13 pt | — |
| Avant et après un exergue | 26 pt | — |
| Approche des capitales (H5, H6) | +60 à +80 ‰ | Les capitales espacées compensent la perte de rythme |
| Approche du texte courant | 0 | Ne jamais utiliser l'approche pour gagner une ligne |

## 10. Grille typographique

### 10.1 Ligne de base

La grille de ligne de base est fixée à **13 pt** à partir du bord supérieur de
la surface de composition (marge de tête). Tout texte de corps 10 pt (et 10,5
pt) s'y cale. Les titres, dont l'interlignage est un multiple de 13, s'y calent
aussi ; les légendes et notes (9,75 pt) s'y raccrochent tous les quatre
interlignes (4 × 9,75 = 39 = 3 × 13).

Activer l'option « aligner sur la grille de ligne de base » pour : le corps,
les H1 à H4, les citations, l'exergue, la première ligne des légendes et des
notes. Ne pas l'activer pour les lignes suivantes des légendes et des notes,
qui suivent leur propre interlignage.

### 10.2 Module horizontal

Le module horizontal est de **4 mm** : gouttières, retraits, marges d'encadré,
espacement des mosaïques, cartouches en sont des multiples. Le bloc de texte de
chaque gabarit est dimensionné pour qu'une colonne soit un multiple entier du
module, à la gouttière près (voir [BOOK_LAYOUT.md](BOOK_LAYOUT.md#4-colonnes-et-gouttières)).

### 10.3 Nombre de lignes par page

| Gabarit | Hauteur de composition | Lignes de 13 pt |
|---------|------------------------|-----------------|
| Carte postale (verso) | 89 mm | 19 |
| A5 portrait | 172 mm | 37 |
| A4 portrait | 245 mm | 53 |
| Livret A5 | 172 mm | 37 |

Ces nombres sont vérifiables dans la grille SVG de chaque gabarit
(`assets/grids/`). Une image de « n lignes » a pour hauteur n × 4,586 mm ;
les hauteurs d'images sont choisies en lignes, ce qui garantit que la légende
qui suit retombe sur la grille.

### 10.4 Correspondance des styles

Dans le logiciel de mise en page, les styles portent les noms du design system
(`MB-P/Corps`, `MB-P/H1`…). La table complète figure dans
[DESIGN_SYSTEM.md](DESIGN_SYSTEM.md#3-styles).

## 11. Conventions typographiques françaises

Ces règles s'appliquent partout, y compris dans les légendes et cartouches.
Elles sont configurées une fois dans le logiciel (dictionnaire français, espaces
automatiques) puis vérifiées à la relecture.

| Cas | Règle | Exemple |
|-----|-------|---------|
| Point-virgule, point d'exclamation, point d'interrogation | Espace fine insécable avant, espace après | « Vraiment ? Oui ! » |
| Deux-points | Espace insécable (mot) avant, espace après | « Lieu : Le Cruet » |
| Guillemets | Chevrons « et », avec espace insécable à l'intérieur | « village » |
| Guillemets de second niveau | Guillemets anglais doubles “ ” | « il disait “demain” » |
| Apostrophe | Typographique ’ (jamais le pied-de-mouche ') | l’église |
| Capitales | Toujours accentuées | École, À, Étienne |
| Sigles | Petites capitales sans points | ISBN, ONF |
| Siècles | Chiffres romains en petites capitales, « e » en exposant | XIXᵉ siècle |
| Nombres | Espace fine insécable comme séparateur de milliers ; virgule décimale | 1 250 habitants ; 3,5 km |
| Dates | Jour en chiffres, mois en toutes lettres bas de casse, année en chiffres | 14 juillet 1923 |
| Intervalles de dates ou de pages | Tiret demi-cadratin sans espace | 1900–1930 ; p. 12–15 |
| Incise | Tiret cadratin avec espaces, ou demi-cadratin selon le choix pour tout le livre | le pont — reconstruit en 1950 — |
| Unités | Espace insécable entre le nombre et l'unité | 148 mm ; 300 dpi |
| Abréviations usuelles | p. (page), vers, éd. (éditeur), coll. (collection), s. d. (sans date), n° | — |
| Titres d'œuvres et de publications | Italique | *Le Dauphiné libéré* |
| Mots étrangers | Italique, sauf s'ils sont passés dans l'usage | *mazot* ; week-end |
| Points de suspension | Caractère unique … suivi d'une espace | « et puis… » |
| Ligatures | fi, fl, ffi activées ; œ et æ obligatoires | œuvre, cœur |

Les espaces fines insécables sont insérées automatiquement par InDesign
(langue « Français ») et par Scribus (« Insertion › Espaces › Espace fine
insécable » ou via le correcteur typographique). Vérifier au préflight qu'aucune
espace ordinaire ne précède un « ? » ou un « ! » en fin de ligne.

## 12. Valeurs par gabarit

| Élément | Carte postale | A5 et livret A5 | A4 |
|---------|---------------|-----------------|----|
| Corps de texte | 8 / 9,75 pt Sans (verso) | 10 / 13 pt Serif | 10,5 / 13 pt Serif, 2 colonnes |
| H1 | 14 / 13 pt Sans SemiBold (recto, titre court) | 30 / 39 pt | 36 / 39 pt |
| H2 | — | 18 / 26 pt | 20 / 26 pt |
| H3 | — | 13 / 13 pt | 14 / 13 pt |
| Légende | 7,5 / 9,75 pt | 8 / 9,75 pt | 8,5 / 9,75 pt |
| Note | — | 7,5 / 9,75 pt | 8 / 9,75 pt (marginale ou bas de page) |
| Folio | — | 8 pt | 8 pt |
| Longueur de ligne | 30 à 45 caractères | ≈ 70 caractères | ≈ 48 caractères par colonne |
| Lignes de base par page | 19 | 37 | 53 |

Les valeurs du corps et des interlignages ne sont pas modifiables projet par
projet. Les seules variables laissées au maquettiste sont le choix entre les
alternatives de familles autorisées, et le style de tiret d'incise.
