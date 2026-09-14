# Mise en page

Ce guide fixe la géométrie des publications MatrixBook : marges, colonnes,
gouttières, fond perdu, zone sûre, pagination, foliotage et composition des
doubles pages. Les valeurs sont données pour les quatre gabarits ; les fiches
de `templates/` les reprennent une à une.

## Sommaire

1. [Anatomie d'une page](#1-anatomie-dune-page)
2. [Fond perdu](#2-fond-perdu)
3. [Zone sûre](#3-zone-sûre)
4. [Colonnes et gouttières](#4-colonnes-et-gouttières)
5. [Marges](#5-marges)
6. [Pagination](#6-pagination)
7. [Foliotage](#7-foliotage)
8. [Composition des doubles pages](#8-composition-des-doubles-pages)
9. [Imposition et chasse](#9-imposition-et-chasse)
10. [Liste de contrôle géométrique](#10-liste-de-contrôle-géométrique)

## 1. Anatomie d'une page

```text
 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐   ← limite du fond perdu (format fini + 3 mm)
 ¦ ┌───────────────────────────────────────┐ ¦   ← format fini (ligne de coupe)
 ¦ │ · · · · · · · · · · · · · · · · · · · │ ¦   ← zone sûre (5 mm à l'intérieur de la coupe)
 ¦ │ ·          marge de tête            · │ ¦
 ¦ │ ·   ┌─────────────────────────────┐ · │ ¦
 ¦ │ ·   │                             │ · │ ¦
 ¦ │ · m │                             │ m · │ ¦
 ¦ │ · a │      surface de             │ a · │ ¦
 ¦ │ · r │      composition            │ r · │ ¦
 ¦ │ · g │      (bloc de texte)        │ g · │ ¦
 ¦ │ · e │                             │ e · │ ¦
 ¦ │ ·   │  ligne de base : 13 pt      │   · │ ¦
 ¦ │ · i │  ─────────────────────────  │ e · │ ¦
 ¦ │ · n │  ─────────────────────────  │ x · │ ¦
 ¦ │ · t │  ─────────────────────────  │ t · │ ¦
 ¦ │ ·   │                             │   · │ ¦
 ¦ │ ·   └─────────────────────────────┘ · │ ¦
 ¦ │ ·          marge de pied            · │ ¦
 ¦ │ ·   titre courant             folio · │ ¦
 ¦ │ · · · · · · · · · · · · · · · · · · · │ ¦
 ¦ └───────────────────────────────────────┘ ¦
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

Quatre rectangles emboîtés définissent toute page MatrixBook :

| Rectangle | Définition | Ce qui peut s'y trouver |
|-----------|------------|-------------------------|
| Fond perdu | Format fini étendu de 3 mm sur chaque côté | Les images et aplats destinés à toucher le bord, prolongés jusqu'ici |
| Format fini | Dimensions de la page après coupe | Tout |
| Zone sûre | Format fini réduit de 5 mm (6 mm en A4) | Tout élément dont la coupe ne doit pas s'approcher : texte, visages, cartouches |
| Surface de composition | Format fini réduit des marges | Le bloc de texte, les images « dans les marges », les encadrés |

Les images à fond perdu traversent librement la zone sûre et les marges ; le
texte ne sort jamais de la surface de composition, hormis le folio et le titre
courant (dans la marge de pied) et les notes marginales (dans la marge
extérieure, en A4).

## 2. Fond perdu

Le fond perdu est la portion d'image ou d'aplat qui dépasse du format fini pour
absorber l'imprécision de la coupe (de l'ordre de ± 1 mm en massicot industriel,
davantage sur un massicot de bureau).

| Paramètre | Valeur MatrixBook | Remarque |
|-----------|-------------------|----------|
| Fond perdu | 3 mm sur les quatre côtés | Standard des imprimeurs européens ; certains demandent 5 mm pour les couvertures, vérifier le devis |
| Fond perdu côté pli (livret agrafé) | 3 mm quand même, sur les pages exportées séparément | Le logiciel d'imposition l'utilise ou l'ignore |
| Fond perdu côté dos (dos carré collé) | 0 mm sur les pages intérieures exportées en pages simples | Le dos n'est pas coupé |
| Traits de coupe | Décalés de 3 mm du format fini (hors fond perdu) | Ils ne doivent jamais entrer dans le fond perdu |

Règles :

1. Toute image ou tout aplat qui touche un bord du format fini est prolongé
   jusqu'à la limite du fond perdu. Jamais de « bord à 0 mm ».
2. Une image à fond perdu est recadrée en conséquence dès le chemin de fer :
   le sujet ne doit pas se trouver dans les 3 mm perdus ni dans les 5 mm de
   zone sûre suivants.
3. Un filet ou un cadre « à ras du bord » est interdit : il révèle toute
   dérive de coupe. Un cadre se place à 5 mm minimum du bord ou n'existe pas.
4. Le fond perdu est déclaré dans le document (InDesign : « Fond perdu » ;
   Scribus : « Fonds perdus ») et inclus à l'export PDF.

## 3. Zone sûre

La zone sûre garantit qu'aucune information n'est coupée ni ne se trouve trop
près du bord pour être lue confortablement.

| Gabarit | Zone sûre (retrait depuis la coupe) |
|---------|-------------------------------------|
| Carte postale | 5 mm |
| A5, livret A5 | 5 mm |
| A4 | 6 mm |

Éléments soumis à la zone sûre : tout texte (y compris en réserve sur une
image), les cartouches, les visages et les détails documentaires d'une image,
les codes-barres, les QR codes, les logos. Sur un livret agrafé, la zone sûre
s'ajoute au retrait dû au pli (voir la section [9](#9-imposition-et-chasse)).

## 4. Colonnes et gouttières

Le module horizontal MatrixBook est de **4 mm**. Les gouttières et les
largeurs de colonnes en découlent.

| Gabarit | Largeur de composition | Colonnes | Gouttière | Largeur de colonne | Usage |
|---------|------------------------|----------|-----------|--------------------|-------|
| Carte postale (verso) | 132 mm | 2 | 4 mm | 64 mm | Correspondance à gauche, adresse à droite |
| A5, livret A5 | 116 mm | 1 | — | 116 mm | Texte courant |
| A5, livret A5 (finales) | 116 mm | 2 | 4 mm | 56 mm | Index, glossaire, notes en fin de volume |
| A5 (mosaïque) | 116 mm | 3 | 4 mm | 36 mm | Grille d'images uniquement |
| A4 | 165 mm | 2 | 5 mm | 80 mm | Texte courant |
| A4 (mosaïque) | 165 mm | 3 | 5 mm | 51,67 mm | Grille d'images uniquement |
| A4 (beau livre) | 165 mm | 1 sur 2 | 5 mm | 80 mm de texte, 80 mm d'image | Une colonne de texte, l'autre réservée aux images |

```text
 A5 — une colonne de texte, grille de 3 modules pour les images

 ┌────────────────────────────────────────────────────┐
 │ marge de tête 16                                   │
 │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐│
 │   │              │ │              │ │              ││  ← 3 modules de 36 mm
 │   │   image      │ │   image      │ │   image      ││     gouttière 4 mm
 │   └──────────────┘ └──────────────┘ └──────────────┘│
 │   ┌────────────────────────────────────────────────┐│
 │   │ texte courant sur 116 mm ≈ 70 caractères       ││
 │   │ ─────────────────────────────────────────────  ││
 │   │ ─────────────────────────────────────────────  ││
 │   └────────────────────────────────────────────────┘│
 │ marge de pied 22                                   │
 └────────────────────────────────────────────────────┘
   int. 14                                    ext. 18
```

Règles :

- Une image occupe un nombre entier de modules en largeur (1, 2 ou 3 en A5 ;
  1, 2 ou 3 en A4) ou la pleine largeur de composition, ou le fond perdu.
- Une image ne s'arrête jamais dans une gouttière.
- Deux colonnes de texte ne sont jamais séparées par un filet vertical ; la
  gouttière suffit.
- En A4, une colonne de texte ne dépasse pas 55 caractères par ligne ; une
  seule colonne de texte sur 165 mm serait illisible à 10,5 pt.

## 5. Marges

Les marges MatrixBook sont progressives (intérieure < tête < extérieure < pied),
selon la tradition du livre, dans une proportion adoucie pour laisser de la
place aux images.

| Gabarit | Tête | Pied | Intérieure | Extérieure | Rapport int : tête : ext : pied |
|---------|------|------|------------|------------|---------------------------------|
| Carte postale (verso) | 8 mm | 8 mm | 8 mm | 8 mm | 1 : 1 : 1 : 1 (pas de reliure) |
| A5 portrait (dos carré) | 16 mm | 22 mm | 14 mm | 18 mm | 1 : 1,14 : 1,29 : 1,57 |
| A4 portrait | 22 mm | 30 mm | 20 mm | 25 mm | 1 : 1,10 : 1,25 : 1,50 |
| Livret agrafé A5 | 16 mm | 22 mm | 12 mm | 18 mm | 1 : 1,33 : 1,50 : 1,83 |

```text
 Double page A5 (dos carré collé) — marges en mm

 ┌────────────────────────┬────────────────────────┐
 │        16              │              16        │
 │   ┌──────────────┐     │     ┌──────────────┐   │
 │18 │              │ 14  │  14 │              │ 18│
 │   │   verso      │     │     │    recto     │   │
 │   │   (pair)     │     │     │   (impair)   │   │
 │   │              │     │     │              │   │
 │   │              │     │     │              │   │
 │   └──────────────┘     │     └──────────────┘   │
 │        22              │              22        │
 └────────────────────────┴────────────────────────┘
                          ↑ pli / dos
```

Pourquoi ces valeurs :

- **Intérieure** : la plus petite, car les deux marges intérieures s'additionnent
  visuellement au pli. Sur un livret agrafé, le cahier s'ouvre à plat, d'où
  12 mm ; sur un dos carré collé, l'ouverture est partielle, d'où 14 mm en A5
  et 20 mm en A4. Au-delà de 200 pages ou sur papier épais, ajouter 2 mm.
- **Extérieure** : le pouce du lecteur ; en A4 elle accueille aussi les notes
  marginales et les légendes en marge.
- **Tête** : plus petite que le pied, pour que le bloc paraisse centré
  optiquement.
- **Pied** : la plus grande ; le folio et le titre courant s'y logent sur la
  première ligne sous la surface de composition.

Les marges sont **symétriques par rapport au pli** (pages en vis-à-vis) : le
document est créé avec l'option « pages en vis-à-vis » ; la marge « intérieure »
est à droite du verso et à gauche du recto.

## 6. Pagination

### 6.1 Rectos et versos

- Les pages **impaires** sont des **rectos** (page de droite) ; les pages
  **paires** sont des **versos** (page de gauche). La page 1 est toujours un
  recto.
- Une double page est donc toujours composée d'une page paire à gauche et
  d'une page impaire à droite : 2–3, 4–5, 6–7…
- Une ouverture de chapitre en double page commence sur une page **paire**.
  Si le chapitre précédent se termine sur une page paire, on ajoute une page
  blanche ou une planche de respiration en page impaire.

### 6.2 Pages liminaires

| Page | Contenu | Folio |
|------|---------|-------|
| 1 (recto) | Faux-titre : titre seul | Masqué |
| 2 (verso) | Blanche, ou frontispice (image pleine page) | Masqué |
| 3 (recto) | Page de titre : titre, sous-titre, auteur, éditeur, lieu et année | Masqué |
| 4 (verso) | Mentions légales : copyright, ISBN, dépôt légal, achevé d'imprimer, crédits photographiques généraux | Masqué |
| 5 (recto) | Sommaire | Masqué |
| 6 (verso) | Blanche, ou avant-propos si court | Masqué |
| 7 (recto) ou 6–7 | Avant-propos, préface, introduction | Visible à partir d'ici |

Dans un livret agrafé, les liminaires se réduisent : la couverture C2 porte
les mentions légales, la page 1 (recto, première page intérieure) le sommaire
ou le faux-titre, et le corps commence page 2 ou 3. Les folios comptent depuis
la première page intérieure ; la couverture n'est pas foliotée.

### 6.3 Nombre de pages et reliure

| Reliure | Multiple obligatoire | Remarque |
|---------|----------------------|----------|
| Piqûre à cheval (agrafé) | 4 | De 8 à 64 pages en pratique ; au-delà, la chasse devient trop importante |
| Dos carré collé | 4 (16 idéalement) | Minimum 40 pages environ pour un dos imprimable ; cahiers de 16 pages en offset |
| Dos cousu | 16 (ou 8) | Cahiers ; vérifier le nombre de pages par cahier avec l'imprimeur |
| Carte postale | 1 recto + 1 verso | Sans objet |

Le chemin de fer est construit dès le départ sur le bon multiple. Une page
manquante se règle en ajoutant une respiration ou une page de sources, jamais
en supprimant le fond perdu d'une page finale.

### 6.4 Pages finales

Ordre recommandé : épilogue ou « aujourd'hui », chronologie, glossaire, index
des lieux et des personnes, sources et bibliographie, crédits photographiques
détaillés, remerciements, table des matières détaillée si le sommaire est
court, achevé d'imprimer (si absent de la page 4).

## 7. Foliotage

| Paramètre | Valeur |
|-----------|--------|
| Style | Sans Regular 8 pt, chiffres tabulaires |
| Position verticale | Première ligne de base sous la surface de composition (soit 13 pt sous le bas du bloc de texte) |
| Position horizontale | Aligné sur la marge extérieure : à gauche sur un verso, à droite sur un recto |
| Titre courant | Sur la même ligne, aligné sur la marge intérieure ; verso : titre du livre ; recto : titre du chapitre en cours |
| Séparateur | Aucun filet entre le titre courant et le folio |

```text
 Verso (pair)                                    Recto (impair)
 ┌────────────────────────────┐ ┌────────────────────────────┐
 │                            │ │                            │
 │   ┌────────────────────┐   │ │   ┌────────────────────┐   │
 │   │                    │   │ │   │                    │   │
 │   │                    │   │ │   │                    │   │
 │   └────────────────────┘   │ │   └────────────────────┘   │
 │   24     LE CRUET, MÉMOIRE │ │   LES TRAVAUX ET LES JOURS 25 │
 │                            │ │                            │
 └────────────────────────────┘ └────────────────────────────┘
      ↑ folio à l'extérieur                 folio à l'extérieur ↑
```

Le folio est **masqué** sur : la couverture et ses trois autres pages, les
liminaires jusqu'au sommaire inclus, les pages blanches, les pleines pages et
pleines ouvertures d'images à fond perdu. Il reste **compté** : la page 12,
même sans folio, est la page 12.

Sur une carte postale, il n'y a ni folio ni titre courant. Sur une série de
cartes postales, un numéro de série (« 3/12 ») figure dans le cartouche du
verso.

## 8. Composition des doubles pages

Les six types de composition de la méthodologie, sur une double page A5.
Légende des schémas : `▓` image, `░` texte, `·` blanc, `│` pli.

### 8.1 Pleine ouverture

```text
 ┌───────────────────────────┬───────────────────────────┐
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ légende ▓▓│
 └───────────────────────────┴───────────────────────────┘
```

Une image, à fond perdu sur les quatre côtés et au pli. Le sujet est vérifié
au pli (rien d'important à moins de 8 mm de chaque côté). Légende en réserve
dans une zone homogène, ou reportée sur la double page suivante avec la mention
« pages précédentes ».

### 8.2 Pleine page + texte

```text
 ┌───────────────────────────┬───────────────────────────┐
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  · · · · · · · · · ·   · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  légende de l'image  →   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 └───────────────────────────┴───────────────────────────┘
```

L'image dominante à droite (point d'entrée), le texte à gauche avec un blanc
sous lui ; la légende de l'image de droite est placée en bas de la page de
gauche. La variante inversée (image à gauche) sert de respiration commentée.

### 8.3 Asymétrique 1/3 – 2/3

```text
 ┌───────────────────────────┬───────────────────────────┐
 │·  TITRE DE CHAPITRE       │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░ chapeau ░░░░   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  · · · · · · · · · · ·   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  légende · · · · · · · · │
 └───────────────────────────┴───────────────────────────┘
```

La page de droite est occupée aux deux tiers de sa hauteur (ou en totalité
avec fond perdu latéral) par l'image ; la légende prend le tiers restant. La
page de gauche porte le titre, le chapeau et le début du texte. C'est la
composition d'ouverture de chapitre par défaut.

### 8.4 Texte + image

```text
 ┌───────────────────────────┬───────────────────────────┐
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  légende · · · · · · · · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 └───────────────────────────┴───────────────────────────┘
```

Le texte domine ; une image demi-page (ou de deux modules) est calée sur la
grille, en haut ou en bas de la page de droite, avec sa légende. Composition
de développement dense ; un encadré peut remplacer l'image.

### 8.5 Mosaïque

```text
 ┌───────────────────────────┬───────────────────────────┐
 │·  ▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓  · │·  ▓▓▓▓▓▓ ▓▓▓▓▓▓ ▓▓▓▓▓▓  · │
 │·  ▓▓▓ 1 ▓▓▓ ▓▓▓▓ 2 ▓▓▓  · │·  ▓ 4 ▓▓ ▓ 5 ▓▓ ▓ 6 ▓▓  · │
 │·  ▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓  · │·  ▓▓▓▓▓▓ ▓▓▓▓▓▓ ▓▓▓▓▓▓  · │
 │·  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 │·  ▓▓▓▓▓▓▓▓ 3 ▓▓▓▓▓▓▓▓▓  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 │·  1. ··· 2. ··· 3. ···    │·  4. ··· 5. ··· 6. ···    │
 └───────────────────────────┴───────────────────────────┘
```

Deux à six images sur les modules de la grille (2 + 1 à gauche, 3 en haut à
droite ici), gouttières de 4 mm, légendes numérotées groupées en bas de
chaque page. Les images d'une même mosaïque ont des hauteurs multiples de la
ligne de base et des largeurs multiples du module. Une mosaïque n'excède pas
six images par double page.

### 8.6 Texte seul

```text
 ┌───────────────────────────┬───────────────────────────┐
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  · · · · · · · · · · · · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·     « exergue centré »   │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  · · · · · · · · · · · · │
 │·  ░░░░░░░░░░░░░░░░░░░░  · │·  ░░░░░░░░░░░░░░░░░░░░  · │
 └───────────────────────────┴───────────────────────────┘
```

Aucune image. Réservé aux liminaires, aux pages finales et aux transitions ;
un exergue ou un encadré rompt le mur de texte. Jamais deux doubles pages
« texte seul » consécutives dans le corps d'un livre illustré.

## 9. Imposition et chasse

### 9.1 Imposition d'un livret agrafé

L'imprimeur (ou le logiciel d'imposition) réorganise les pages par feuilles
pliées. Pour un livret de 8 pages :

```text
 Feuille 1, extérieur          Feuille 1, intérieur
 ┌───────────┬───────────┐     ┌───────────┬───────────┐
 │           │           │     │           │           │
 │     8     │     1     │     │     2     │     7     │
 │           │           │     │           │           │
 └───────────┴───────────┘     └───────────┴───────────┘

 Feuille 2, extérieur          Feuille 2, intérieur
 ┌───────────┬───────────┐     ┌───────────┬───────────┐
 │           │           │     │           │           │
 │     6     │     3     │     │     4     │     5     │
 │           │           │     │           │           │
 └───────────┴───────────┘     └───────────┴───────────┘
```

La somme des deux pages d'une même face vaut toujours le nombre de pages + 1
(8 + 1 = 9 : 8 + 1, 2 + 7, 6 + 3, 4 + 5). Le maquettiste **n'impose pas** :
il livre un PDF en pages simples dans l'ordre de lecture ; l'imposition est
faite en prépresse. Il vérifie seulement que le nombre de pages est un
multiple de 4.

### 9.2 Chasse (creep)

Dans un livret agrafé, les feuilles intérieures dépassent des feuilles
extérieures à l'ouverture : c'est la chasse. Après rognage, les marges
extérieures des pages centrales sont plus petites que celles des pages
externes.

```text
 Coupe transversale d'un livret de 6 feuilles (24 pages), avant rognage

     ┌──────────────────────────────┐   ← feuille extérieure (pages 1, 24…)
     │ ┌──────────────────────────┐ │
     │ │ ┌──────────────────────┐ │ │
     │ │ │ ┌──────────────────┐ │ │ │
     │ │ │ │ ┌──────────────┐ │ │ │ │
     │ │ │ │ │ ┌──────────┐ │ │ │ │ │   ← feuille centrale (pages 12, 13)
   ══╧═╧═╧═╧═╧═╧══════════╧═╧═╧═╧═╧═╧══  agrafes
                                    ↑ tranche à rogner : la chasse
```

| Grammage du papier | Chasse par feuille (approx.) | Chasse totale, 24 pages (6 feuilles) | Chasse totale, 48 pages (12 feuilles) |
|--------------------|------------------------------|--------------------------------------|---------------------------------------|
| 90 g/m² | 0,10 mm | 0,6 mm | 1,2 mm |
| 115 g/m² | 0,13 mm | 0,8 mm | 1,6 mm |
| 135 g/m² | 0,16 mm | 1,0 mm | 1,9 mm |
| 170 g/m² | 0,20 mm | 1,2 mm | 2,4 mm |

Conséquences pour la maquette :

- La zone sûre de 5 mm absorbe la chasse jusqu'à 48 pages sur papier standard.
- Au-delà, ou pour un livret de plus de 32 pages sur papier épais, ne rien
  placer à moins de 7 mm du bord extérieur sur les pages centrales.
- La compensation de la chasse (décalage progressif des pages vers le pli)
  est réglée par l'imprimeur dans l'imposition : il faut le lui demander
  explicitement (« compensation de la chasse activée »).

### 9.3 Dos carré collé

Sur un dos carré collé, l'ouverture n'est pas plane : 3 à 5 mm de chaque page
disparaissent visuellement dans le dos. Une image en pleine ouverture est
prolongée de ce recouvrement de part et d'autre du pli (l'imprimeur peut le
faire en prépresse à partir d'une image continue si elle est livrée en une seule
page double ; sinon, on le prévoit dans la maquette). Le texte, lui, ne
s'approche jamais à moins de 14 mm du dos (marge intérieure).

## 10. Liste de contrôle géométrique

- [ ] Document créé aux dimensions finies exactes du gabarit, en pages en vis-à-vis.
- [ ] Fond perdu de 3 mm déclaré et respecté par toutes les images et aplats en bord de page.
- [ ] Aucun texte, visage, logo ou code hors de la zone sûre.
- [ ] Marges du gabarit appliquées sans exception (les images à fond perdu sont la seule chose qui les traverse).
- [ ] Colonnes et gouttières du gabarit ; aucune image arrêtée dans une gouttière.
- [ ] Nombre de pages compatible avec la reliure ; page 1 en recto.
- [ ] Chaque ouverture de chapitre en double page, commençant sur une page paire.
- [ ] Folios présents sur les pages courantes, masqués sur liminaires, planches à fond perdu et pages blanches.
- [ ] Images en pleine ouverture vérifiées au pli (8 mm de chaque côté) et prolongées du recouvrement en dos carré collé.
- [ ] Chasse évaluée pour un livret agrafé, compensation demandée à l'imprimeur.
