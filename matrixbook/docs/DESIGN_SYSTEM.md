# Design system

Le design system MatrixBook est le vocabulaire graphique partagé par toutes les
publications : palette, styles nommés, icônes, cartouches, encadrés, appels de
note et conventions graphiques. Il s'appuie sur la
[typographie](TYPOGRAPHY.md) et la [mise en page](BOOK_LAYOUT.md) ; il est
conçu pour l'impression CMJN d'abord, l'écran ensuite.

## Sommaire

1. [Principes](#1-principes)
2. [Palette](#2-palette)
3. [Styles](#3-styles)
4. [Icônes](#4-icônes)
5. [Cartouches](#5-cartouches)
6. [Encadrés](#6-encadrés)
7. [Appels de note](#7-appels-de-note)
8. [Conventions graphiques](#8-conventions-graphiques)
9. [Nomenclature des fichiers](#9-nomenclature-des-fichiers)

## 1. Principes

- **La couleur signale, elle ne décore pas.** Dans une publication
  patrimoniale, l'image d'archive est la couleur ; le design system reste en
  retrait : noir, gris, parchemin, et une ou deux teintes d'accent par projet.
- **Tout est nommé.** Chaque style, chaque couleur, chaque objet porte un nom
  préfixé `MB-`. Un élément sans style nommé est une erreur de maquette.
- **Tout est en CMJN.** Chaque couleur a une définition CMJN de référence ;
  les valeurs RVB et hexadécimales sont des conversions indicatives pour les
  usages écran (PDF interactif, site du projet).
- **Pas d'effets.** Ni ombre portée, ni biseau, ni dégradé, ni contour
  lumineux, ni coins arrondis. La seule transparence admise est celle des
  teintes en pourcentage (aplats d'encadrés) et des réserves de texte.

## 2. Palette

### 2.1 Couleurs de base

Présentes dans toutes les publications.

| Nom | Nuance | CMJN | RVB (sRGB, indicatif) | Hex | Usage |
|-----|--------|------|-----------------------|-----|-------|
| `MB-Noir texte` | Noir | 0 / 0 / 0 / 100 | 35, 31, 32 | `#231F20` | Tout le texte, les filets, les icônes |
| `MB-Noir riche` | Noir profond | 60 / 40 / 40 / 100 | 0, 0, 0 | `#000000` | Aplats de plus de 20 × 20 mm uniquement (couverture, fond de planche) |
| `MB-Gris pierre` | Gris moyen | 0 / 0 / 0 / 60 | 128, 130, 133 | `#808285` | Sources, folios, texte secondaire, filets fins |
| `MB-Gris brume` | Gris clair | 0 / 0 / 0 / 15 | 220, 221, 222 | `#DCDDDE` | Fonds de tableaux, filets de séparation |
| `MB-Parchemin` | Blanc cassé chaud | 3 / 4 / 12 / 0 | 246, 240, 224 | `#F6F0E0` | Fonds d'encadrés « Repère », de cartouches, fond de verso de carte postale |
| `MB-Papier` | Blanc | 0 / 0 / 0 / 0 | 255, 255, 255 | `#FFFFFF` | Réserves, texte en réserve |

### 2.2 Couleurs d'accent

Un projet choisit **une** teinte principale et, au plus, **une** teinte
secondaire parmi les cinq suivantes. La teinte principale porte les cartouches
et les titres de chapitre s'ils sont colorés ; la secondaire est réservée aux
encadrés « Attention » et « Regard ».

| Nom | Nuance | CMJN | RVB (sRGB, indicatif) | Hex | Caractère |
|-----|--------|------|-----------------------|-----|-----------|
| `MB-Ocre patrimoine` | Ocre doré | 0 / 35 / 85 / 10 | 224, 162, 58 | `#E0A23A` | Chaleur, pierre, archives ; teinte par défaut |
| `MB-Bleu ardoise` | Bleu gris profond | 75 / 45 / 20 / 25 | 58, 94, 124 | `#3A5E7C` | Eau, montagne, cartes ; sobre |
| `MB-Rouge cinabre` | Rouge brique | 5 / 95 / 90 / 10 | 200, 36, 42 | `#C8242A` | Signalement, avertissement ; à petite dose |
| `MB-Vert sauge` | Vert gris doux | 45 / 10 / 45 / 20 | 122, 158, 133 | `#7A9E85` | Nature, agriculture, parcours |
| `MB-Brun sépia` | Brun chaud | 30 / 55 / 70 / 40 | 123, 86, 54 | `#7B5636` | Photographie ancienne, bois, cuir |

Les valeurs RVB sont obtenues par conversion depuis le CMJN sous profil
FOGRA39 (voir [COLOR_MANAGEMENT.md](COLOR_MANAGEMENT.md)) ; elles servent à
l'écran, jamais à redéfinir la couleur d'impression.

### 2.3 Teintes

Chaque couleur d'accent existe en trois teintes, obtenues par pourcentage de
la couleur de référence (et non par ajout de blanc RVB) :

| Teinte | Pourcentage | Usage |
|--------|-------------|-------|
| 100 % | Pleine | Cartouches, filets d'encadré, icônes colorées, titres colorés |
| 30 % | Moyenne | Fonds de tableaux de chronologie, bandeaux |
| 10 % | Légère | Fonds d'encadrés colorés |

Le texte noir sur une teinte de 10 % ou 30 % reste lisible ; le texte en
réserve (blanc) n'est autorisé que sur une teinte à 100 % de `MB-Bleu
ardoise`, `MB-Brun sépia`, `MB-Rouge cinabre` ou sur `MB-Noir riche`. Jamais
de texte blanc sur `MB-Ocre patrimoine` ni `MB-Vert sauge` (contraste
insuffisant).

### 2.4 Contraste et accessibilité

| Combinaison | Autorisée | Remarque |
|-------------|-----------|----------|
| Noir texte sur papier, parchemin, gris brume, teintes 10 % et 30 % | Oui | Usage courant |
| Gris pierre sur papier | Oui, corps ≥ 8 pt | Texte secondaire seulement |
| Gris pierre sur parchemin ou teinte 10 % | Non | Contraste insuffisant |
| Papier sur bleu ardoise, brun sépia, rouge cinabre, noir riche | Oui, corps ≥ 8 pt | Titres, cartouches, légendes en réserve |
| Papier sur ocre, vert sauge | Non | — |
| Couleur d'accent sur couleur d'accent | Non | — |

## 3. Styles

Les styles sont nommés avec un préfixe de famille et une barre oblique pour
former des groupes dans le logiciel : `MB-P/` paragraphes, `MB-C/` caractères,
`MB-O/` objets, `MB-T/` tableaux. Les valeurs sont celles de
[TYPOGRAPHY.md](TYPOGRAPHY.md).

### 3.1 Styles de paragraphe

| Style | Base | Description |
|-------|------|-------------|
| `MB-P/Corps` | — | Texte courant 10 / 13 pt justifié, retrait 4 mm |
| `MB-P/Corps premier` | Corps | Sans retrait de première ligne |
| `MB-P/Chapeau` | Corps | Italique 11 / 13 pt, ferré à gauche, sans retrait |
| `MB-P/H1` … `MB-P/H6` | — | Échelle des titres |
| `MB-P/H1 couverture` | H1 | Corps libre 36 à 48 pt, couverture uniquement |
| `MB-P/Citation bloc` | Corps | Italique, retraits 8 mm, avant et après 13 pt |
| `MB-P/Citation source` | — | Sans 8 / 13 pt, aligné à droite, tiret cadratin |
| `MB-P/Exergue` | — | Serif italique 16 / 26 pt |
| `MB-P/Légende` | — | Sans 8 / 9,75 pt, ferré à gauche |
| `MB-P/Légende réserve` | Légende | En blanc papier |
| `MB-P/Légende mosaïque` | Légende | Avec numéro tabulaire et retrait négatif de 4 mm |
| `MB-P/Note` | — | Serif 7,5 / 9,75 pt |
| `MB-P/Note marginale` | Note | Sans 7,5 / 9,75 pt |
| `MB-P/Folio` | — | Sans 8 pt tabulaire |
| `MB-P/Titre courant` | Folio | Petites capitales, approche +50 |
| `MB-P/Cartouche` | — | Sans 7,5 / 13 pt capitales, approche +80 |
| `MB-P/Encadré titre` | H5 | Sans SemiBold 9 / 13 pt capitales |
| `MB-P/Encadré corps` | — | Sans 8,5 / 9,75 pt ferré à gauche |
| `MB-P/Sommaire entrée` | Corps | Avec taquet de points de conduite et folio à droite |
| `MB-P/Index entrée` | — | Serif 8,5 / 9,75 pt, retrait négatif 3 mm |
| `MB-P/Tableau cellule` | — | Sans 8 / 9,75 pt |
| `MB-P/Tableau en-tête` | Tableau cellule | SemiBold, capitales, approche +40 |

### 3.2 Styles de caractère

| Style | Description |
|-------|-------------|
| `MB-C/Italique` | Italique de la même famille (titres d'œuvres, mots étrangers) |
| `MB-C/Petites capitales` | Petites capitales OpenType, approche +40 (sigles, siècles) |
| `MB-C/Exposant` | Exposant OpenType (appels de note, « e » des siècles) |
| `MB-C/Légende sujet` | Sans SemiBold |
| `MB-C/Légende source` | Sans Italic, gris pierre |
| `MB-C/Chiffres tabulaires` | Chiffres tabulaires alignés (tableaux, chronologies) |
| `MB-C/Accent` | Couleur d'accent principale à 100 % (rare : un mot-clé dans un cartouche) |

### 3.3 Styles d'objet

| Style | Description |
|-------|-------------|
| `MB-O/Image` | Bloc image sans contour, ajustement proportionnel, calé sur la grille |
| `MB-O/Image document` | Bloc image avec filet 0,25 pt `MB-Gris pierre` (documents à fond blanc : cartes postales, plans, lettres) |
| `MB-O/Image fond perdu` | Bloc image étendu de 3 mm hors page |
| `MB-O/Cartouche` | Bloc texte fond `MB-Parchemin` ou accent 100 %, marges internes 1,5 mm / 3 mm, hauteur 1 ligne de base |
| `MB-O/Encadré` | Bloc texte fond accent 10 % ou parchemin, filet gauche 1 pt accent 100 %, marges internes 4 mm |
| `MB-O/Encadré attention` | Encadré avec filet gauche `MB-Rouge cinabre` ou accent secondaire |
| `MB-O/Filet séparateur` | Filet horizontal 0,25 pt `MB-Gris brume`, longueur 20 mm |
| `MB-O/Filet chapitre` | Filet horizontal 1 pt accent 100 %, largeur d'une colonne |

### 3.4 Style de tableau

| Style | Description |
|-------|-------------|
| `MB-T/Standard` | Filets horizontaux 0,25 pt `MB-Gris brume` uniquement, en-tête sur fond `MB-Gris brume`, pas de filet vertical, marges de cellule 1,5 mm / 2 mm, texte `MB-P/Tableau cellule` |
| `MB-T/Chronologie` | Standard avec première colonne (dates) en `MB-C/Chiffres tabulaires` SemiBold et fond accent 30 % sur les lignes de rupture (changement de décennie) |

## 4. Icônes

Le jeu d'icônes est décrit dans [assets/icons/README.md](../assets/icons/README.md)
(16 icônes au trait, 24 × 24, trait 1,5). Rappel des règles d'usage :

| Contexte | Taille | Couleur | Position |
|----------|--------|---------|----------|
| Légende | 4 mm | `MB-Noir texte` | Avant le sujet, centrée sur la hauteur d'x, espace 1 mm |
| Cartouche | 5 mm | Couleur du texte du cartouche | À gauche du texte, espace 1,5 mm |
| Encadré | 6 mm | Accent 100 % de l'encadré | À gauche du titre H5 |
| Ouverture de chapitre | 8 mm | Accent 100 % | Au-dessus du H6 de numéro de chapitre |

Une icône a une seule signification dans toute la publication. Le tableau
d'affectation icône → fonction est repris dans le README du jeu d'icônes.

## 5. Cartouches

Le cartouche est une courte étiquette encadrée qui identifie, localise ou date.
Il existe en quatre types.

### 5.1 Types

| Type | Contenu | Fond | Texte | Icône | Où |
|------|---------|------|-------|-------|----|
| Cartouche de planche | Numéro et titre de la planche (« Planche 4 · La place ») | Accent 100 % | Papier, `MB-P/Cartouche` | Aucune | Angle supérieur extérieur d'une planche ou d'une mosaïque |
| Cartouche de lieu | Toponyme, éventuellement altitude | `MB-Parchemin` | `MB-Noir texte`, `MB-P/Cartouche` | `lieu` | Sous ou sur une image de lieu, angle inférieur gauche |
| Cartouche de date | Date ou fourchette | `MB-Parchemin` | `MB-Noir texte`, `MB-P/Cartouche` | `date` | Accolé au cartouche de lieu, à sa droite |
| Cartouche éditeur | Nom de l'éditeur ou de l'association, logo, année | Aucun ou `MB-Noir riche` | `MB-P/Cartouche` | Logo | Bas de la couverture ; verso de la carte postale |

### 5.2 Anatomie

```text
 hauteur : 1 ligne de base (4,586 mm)
 ┌──────────────────────────────────┐
 │ ⌖  LE CRUET · 1 050 m           │   ← icône 5 mm, espace 1,5 mm, texte capitales 7,5 pt approche +80
 └──────────────────────────────────┘
   ↑ marge interne gauche 3 mm         ↑ marge interne droite 3 mm

 Cartouches de lieu et de date accolés (espace 1 mm) :
 ┌───────────────────┐ ┌────────────────┐
 │ ⌖  LE CRUET       │ │ ▤  VERS 1912   │
 └───────────────────┘ └────────────────┘

 Cartouche de planche, sur fond accent, en réserve :
 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
 ▓ PLANCHE 4 · LA PLACE ▓
 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
```

### 5.3 Règles

- Hauteur fixe d'une ligne de base ; largeur ajustée au contenu ; un cartouche
  ne se coupe jamais sur deux lignes. Un texte trop long est abrégé, pas
  réduit.
- Un cartouche posé sur une image se place dans une zone homogène, à 4 mm du
  bord de l'image, jamais sur un détail documentaire.
- Sur toute la publication, les cartouches de lieu et de date sont
  **toujours au même angle** de l'image (par défaut l'angle inférieur gauche).
- Les cartouches ne remplacent pas la légende : ils la résument.

## 6. Encadrés

L'encadré isole un contenu complémentaire du texte courant. Cinq types,
chacun avec son icône et sa couleur.

### 6.1 Types

| Type | Titre H5 | Icône | Filet gauche | Fond | Contenu |
|------|----------|-------|--------------|------|---------|
| Repère | « Repère » | `repere` | Accent principal 100 % | Accent principal 10 % | Définition, contexte historique ou géographique, chiffres clés |
| Note | « Le saviez-vous ? » ou « Note » | `note` | `MB-Gris pierre` | `MB-Parchemin` | Anecdote, précision, complément |
| Regard | « Regard » | `oeil` | Accent secondaire 100 % (ou principal) | Papier, sans fond | Lecture guidée d'une image : « observez, en bas à gauche… » ; toujours accolé à l'image |
| Témoignage | Prénom et initiale du témoin | `temoin` | `MB-Brun sépia` 100 % | `MB-Brun sépia` 10 % | Citation orale, en `MB-P/Citation bloc` |
| Attention | « Attention » ou « Incertitude » | `attention` | `MB-Rouge cinabre` 100 % | `MB-Rouge cinabre` 10 % | Datation incertaine, attribution douteuse, mise en garde (site privé, danger) |

### 6.2 Anatomie

```text
 largeur : 1 colonne (ou 2 modules en A5)
 ┃ ◎  REPÈRE                                   ← filet gauche 1 pt, icône 6 mm, titre H5
 ┃
 ┃  Le cadastre napoléonien, levé entre 1808   ← corps 8,5 / 9,75 pt, marges internes 4 mm
 ┃  et 1850, est la première représentation
 ┃  parcellaire exhaustive du territoire
 ┃  communal. Celui du Cruet date de 1812.
 ┃
 ┃  ▸ Voir le plan p. 3                        ← renvoi facultatif, icône fleche 4 mm
```

### 6.3 Règles

- Un encadré fait entre 200 et 600 signes ; au-delà, c'est une section de
  texte.
- Un encadré occupe une colonne (ou deux modules en A5) et une hauteur
  multiple de la ligne de base ; il se cale en haut ou en bas de la surface
  de composition, jamais au milieu d'une colonne de texte.
- Un encadré ne se coupe pas sur deux pages ni sur deux colonnes.
- Au plus un encadré par page, deux par double page.
- Les types ne se mélangent pas : un « Repère » n'a pas de teinte rouge, un
  « Témoignage » n'a pas d'icône `note`.

## 7. Appels de note

| Élément | Règle |
|---------|-------|
| Forme | Chiffre arabe en exposant OpenType (`MB-C/Exposant`), sans parenthèse ni crochet |
| Numérotation | Continue par chapitre ; repart à 1 à chaque chapitre |
| Position | Collé au mot, avant la ponctuation : « la scierie¹. » ; après un « ? » ou un « ! » |
| Note de l'éditeur | Astérisque `*`, puis `**` si deux sur la même page |
| Dans les titres | Interdit |
| Dans les légendes | Interdit ; la source est écrite en clair |
| Dans un encadré | Interdit ; la source est écrite en fin d'encadré en `MB-P/Citation source` |
| Renvoi interne | « (voir p. 24) » en texte ; icône `fleche` + « p. 24 » en légende ou encadré |
| Renvoi de figure | « (fig. 3.2) » : numéro de chapitre, point, numéro de figure dans le chapitre |

Le bloc de notes en bas de page commence par un filet de 0,25 pt sur 20 mm
(`MB-O/Filet séparateur`), suivi d'une ligne de base vide. En A4, la note
marginale se place dans la marge extérieure, alignée sur la ligne de base de
l'appel ; elle ne descend pas sous la surface de composition.

## 8. Conventions graphiques

### 8.1 Filets

| Filet | Épaisseur | Couleur | Usage |
|-------|-----------|---------|-------|
| Filet fin | 0,25 pt | `MB-Gris brume` ou `MB-Gris pierre` | Tableaux, séparateur de notes, contour des documents à fond blanc |
| Filet moyen | 0,5 pt | `MB-Noir texte` | Tableaux : ligne sous l'en-tête |
| Filet fort | 1 pt | Accent 100 % | Filet gauche d'encadré, filet d'ouverture de chapitre |

Aucun filet inférieur à 0,25 pt (non reproductible en offset) ; aucun filet
supérieur à 1 pt hors aplat. Les filets sont horizontaux ou verticaux ;
jamais obliques, jamais en pointillé dans le corps (le pointillé est réservé
aux schémas et aux cartes).

### 8.2 Images

- **Photographies** : sans contour. Recadrées selon le chemin de fer, jamais
  déformées, jamais retournées.
- **Documents à fond blanc** (cartes postales, plans, lettres, coupures de
  presse) : contour 0,25 pt `MB-Gris pierre` (`MB-O/Image document`) pour
  distinguer le document du papier, reproduits entiers avec leurs bords.
- **Détail** : un détail agrandi d'un document est signalé par « (détail) »
  en légende et, si l'original figure sur la même double page, par un cadre
  fin 0,5 pt accent sur l'original délimitant la zone.
- **Avant / après** : deux images de même cadrage, même taille, côte à côte
  (gouttière 4 mm) ou l'une sous l'autre ; légende commune avec dates en
  tête : « 1912 / 2025 ».
- **Numérotation des figures** : chapitre.numéro, reprise dans la légende de
  mosaïque et dans les renvois.

### 8.3 Cartes et schémas

- Fond `MB-Parchemin` ou papier, tracés en `MB-Noir texte` et gris, une seule
  couleur d'accent pour le parcours ou le point d'intérêt.
- Échelle graphique obligatoire ; flèche du nord en haut à droite.
- Typographie des cartes : Sans 7,5 pt, capitales espacées pour les
  toponymes majeurs, bas de casse italique pour les cours d'eau.

### 8.4 Ce qui est interdit

Ombres portées, biseaux, dégradés, contours lumineux, coins arrondis, cadres
ornementaux, images inclinées, textes courbes, polices décoratives, plus de
deux couleurs d'accent, texte en capitales sur plus de deux lignes, texte
justifié en corps inférieur à 10 pt, filets obliques, effets de transparence
autres que les teintes.

## 9. Nomenclature des fichiers

Une nomenclature stable permet de retrouver, dix ans plus tard, l'original
d'une image publiée.

| Type de fichier | Modèle | Exemple |
|-----------------|--------|---------|
| Image source (numérisation brute, archivée intacte) | `SRC_<fonds>_<cote>.tif` | `SRC_AD73_6Fi1234.tif` |
| Image de travail (traitée, recadrée) | `CH<chapitre>_<figure>_<sujet>_<annee>.tif` | `CH03_012_place-eglise_1912.tif` |
| Image écran (aperçu, chemin de fer) | Même nom, suffixe `_web.jpg` | `CH03_012_place-eglise_1912_web.jpg` |
| Document de mise en page | `MB_<projet>_<format>_v<version>.<ext>` | `MB_le-cruet_livret-a5_v03.indd` |
| PDF imprimeur | `MB_<projet>_<format>_<partie>_v<version>_X4.pdf` | `MB_le-cruet_livret-a5_interieur_v03_X4.pdf` |
| PDF couverture | Idem, partie `couverture` | `MB_le-cruet_livret-a5_couverture_v03_X4.pdf` |
| Bon à tirer signé | Idem, suffixe `_BAT` | `MB_le-cruet_livret-a5_interieur_v03_X4_BAT.pdf` |

Règles : minuscules sans accent pour les parties libres, tirets entre les
mots d'un sujet, tirets bas entre les champs, numéro de version sur deux
chiffres, jamais de « final » ni de « ok » dans un nom de fichier.
