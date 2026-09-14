# MatrixBook — Méthodologie éditoriale

Ce document décrit la méthode MatrixBook pour concevoir une publication
illustrée : livre, livret, carte postale, catalogue ou monographie patrimoniale.
Il précède la mise en page proprement dite. Les valeurs techniques (marges,
corps de texte, couleurs) sont détaillées dans les guides compagnons :
[TYPOGRAPHY.md](TYPOGRAPHY.md), [BOOK_LAYOUT.md](BOOK_LAYOUT.md) et
[DESIGN_SYSTEM.md](DESIGN_SYSTEM.md).

## Sommaire

1. [La matrice](#1-la-matrice)
2. [Narration visuelle](#2-narration-visuelle)
3. [Hiérarchie des pages](#3-hiérarchie-des-pages)
4. [Rythme éditorial](#4-rythme-éditorial)
5. [Illustrations](#5-illustrations)
6. [Légendes](#6-légendes)
7. [Doubles pages](#7-doubles-pages)
8. [Équilibre texte / image](#8-équilibre-texte--image)
9. [Liste de contrôle méthodologique](#9-liste-de-contrôle-méthodologique)

## 1. La matrice

Une publication MatrixBook repose sur trois invariants, définis une fois pour
toute la collection et jamais renégociés page par page :

| Invariant | Définition | Où il est fixé |
|-----------|------------|----------------|
| La grille | Marges, colonnes, gouttières, ligne de base | [BOOK_LAYOUT.md](BOOK_LAYOUT.md) |
| L'échelle | Corps et interlignages des niveaux de texte | [TYPOGRAPHY.md](TYPOGRAPHY.md) |
| Le vocabulaire | Palette, styles, cartouches, encadrés, icônes | [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) |

La matrice est ce qui rend une carte postale, un livret et un beau livre
reconnaissables comme les membres d'une même famille. Elle libère le maquettiste
de la plupart des décisions locales : la question n'est plus « où placer cette
image ? » mais « quel type de double page cette image appelle-t-elle ? ».

La méthode se déroule en cinq étapes, dans cet ordre :

1. **Corpus** : inventaire des images et des textes disponibles, avec leur
   provenance et leurs droits.
2. **Récit** : définition de l'arc narratif et découpage en séquences.
3. **Chemin de fer** : attribution d'un rôle et d'un type de composition à
   chaque double page.
4. **Maquette** : composition dans la grille, avec les styles du design system.
5. **Production** : préparation des images, contrôle prépresse et export
   ([PRINT_PIPELINE.md](PRINT_PIPELINE.md), [EXPORT_GUIDE.md](EXPORT_GUIDE.md)).

Les étapes 1 à 3 se font sans logiciel de mise en page. C'est délibéré : les
publications ratées le sont presque toujours parce qu'on a ouvert InDesign trop
tôt.

## 2. Narration visuelle

### 2.1 Une publication est une séquence

Le lecteur d'un livre illustré ne lit pas des pages, il traverse une suite de
doubles pages. Chaque ouverture est perçue d'abord globalement (masses, images,
blancs), puis parcourue (titres, légendes), enfin lue (texte courant). Concevoir
la narration visuelle, c'est décider ce que le lecteur perçoit à chaque
ouverture et dans quel ordre.

L'arc narratif d'une publication MatrixBook comporte toujours quatre temps :

| Temps | Fonction | Part indicative |
|-------|----------|-----------------|
| Ouverture | Installer le sujet, le ton, la promesse | 10 % |
| Développement | Dérouler les séquences thématiques ou chronologiques | 70 % |
| Respirations | Suspendre le flux, laisser une image parler seule | 10 % |
| Clôture | Rassembler, ouvrir vers l'aujourd'hui, donner les sources | 10 % |

### 2.2 Le fil conducteur

Avant toute maquette, formulez le fil conducteur en une phrase de la forme
« Ce livre montre *quoi*, à travers *quel matériau*, pour *qui* ». Par exemple :
« Ce livret montre la transformation d'un village de montagne entre 1900 et 1980,
à travers des cartes postales et des photographies familiales, pour les habitants
et les visiteurs de passage. » Tout ce qui ne sert pas cette phrase est un
candidat à la coupe.

Trois structures de fil conducteur couvrent l'essentiel des projets
patrimoniaux :

- **Chronologique** : de l'état ancien à l'état actuel. Naturelle pour les fonds
  de cartes postales ; le risque est la monotonie, à corriger par des
  respirations et des comparaisons avant/après.
- **Topographique** : un parcours dans l'espace (rue par rue, hameau par hameau).
  Idéale pour un livret de visite ; demande une carte de situation en ouverture.
- **Thématique** : par usages (le travail, la fête, l'école, l'eau). Convient aux
  fonds hétérogènes ; chaque thème devient un chapitre à l'ouverture marquée.

### 2.3 Le chemin de fer

Le chemin de fer est la traduction du récit en doubles pages. On le construit
sur une feuille ou un tableau, jamais dans le logiciel de mise en page. Pour
chaque double page, on note : les numéros de pages, le rôle narratif, le type
de composition (voir la section [7](#7-doubles-pages)), le texte prévu en
nombre de signes, les images prévues avec leur identifiant, et le ratio
texte/image visé.

Un exemple complet est fourni dans
[assets/examples/chemin-de-fer-livret-a5.md](../assets/examples/chemin-de-fer-livret-a5.md).
Le chemin de fer se relit à voix haute, rôle après rôle : si la succession
n'évoque rien, la maquette ne racontera rien non plus.

### 2.4 Points d'entrée et points de fuite

Sur chaque double page, le regard entre par un point dominant (l'image la plus
grande, le titre, un contraste fort) et ressort par un point secondaire. Placez
le point d'entrée dans le tiers supérieur, de préférence sur la page de droite
pour une ouverture de chapitre, et le point de fuite en bas à droite, là où la
main tourne la page. Une double page sans point d'entrée identifiable est une
double page que le lecteur saute.

## 3. Hiérarchie des pages

Toutes les pages n'ont pas la même importance. MatrixBook distingue sept
niveaux, chacun avec une composition et un traitement typographique dédiés.

| Niveau | Page | Composition | Traitement |
|--------|------|-------------|------------|
| 0 | Couverture (C1) | Image à fond perdu, titre, cartouche éditeur | H1 couverture, palette pleine |
| 1 | Pages liminaires | Faux-titre, page de titre, mentions légales, sommaire | Texte seul, grands blancs |
| 2 | Ouverture de chapitre | Toujours une double page ; image dominante | H1, chapeau, folio masqué possible |
| 3 | Page courante | Texte et images dans la grille | Corps, H2/H3, légendes |
| 4 | Planche | Image ou mosaïque, texte réduit aux légendes | Légendes, cartouche |
| 5 | Respiration | Pleine page ou pleine ouverture, un seul élément | Exergue ou légende longue |
| 6 | Pages finales | Chronologie, index, glossaire, sources, remerciements | Corps réduit, colonnes |

Trois règles d'application :

- **Une ouverture de chapitre commence toujours sur une double page**, même si
  cela impose une page blanche ou une planche avant elle. Un chapitre qui
  commence à droite sur une page isolée n'existe pas pour le lecteur.
- **Le niveau se lit sans lire.** Un lecteur qui feuillette doit distinguer une
  ouverture de chapitre d'une page courante à un mètre de distance. Cela passe
  par la taille de l'image dominante et par le blanc, pas par la couleur du titre.
- **Les pages liminaires et finales sont sobres.** Elles cadrent l'objet ; elles
  ne concurrencent pas le corps.

## 4. Rythme éditorial

### 4.1 Alternance

Le rythme naît de l'alternance entre des doubles pages denses (texte, mosaïque)
et des doubles pages aérées (pleine page, respiration). La règle de base
MatrixBook : **jamais plus de trois doubles pages denses consécutives** sans
respiration, et **jamais deux respirations consécutives** hors ouverture de
chapitre.

Représentez la densité de chaque double page par une barre de quatre segments
(part d'image) et observez la courbe. Un bon rythme ressemble à une
respiration : montée, plateau, relâchement. Un rythme plat (toutes les doubles
pages à 50/50) est le défaut le plus fréquent des publications amateurs : il est
confortable à produire et ennuyeux à lire.

### 4.2 Cadence des chapitres

Dans un livre de 96 à 160 pages, visez des chapitres de 8 à 16 pages, de
longueur comparable (écart maximal du simple au double). Dans un livret de 16 à
32 pages, deux ou trois chapitres suffisent. Une carte postale n'a pas de
chapitre : son rythme est celui de la série (une carte, un thème, un cartouche
identique).

### 4.3 Répétition et variation

Le rythme se construit aussi sur des motifs récurrents : un cartouche de lieu
toujours au même endroit, une ouverture de chapitre toujours construite de la
même façon, une comparaison avant/après toujours en fin de chapitre. Ces
répétitions rassurent le lecteur ; les variations (une image qui déborde de la
grille, un exergue en pleine page) n'ont de force que parce que la règle est
établie. Ne variez qu'une chose à la fois.

### 4.4 Le blanc

Le blanc n'est pas un vide à remplir, c'est un matériau. Il isole, hiérarchise,
repose. Dans MatrixBook, le blanc est budgété : une page courante conserve au
moins 20 % de sa surface de composition vide (hors marges) ; une respiration en
conserve au moins 50 %. Un texte qui « ne rentre pas » se coupe ou change de
page ; il ne grignote jamais le blanc.

## 5. Illustrations

### 5.1 Sélection

Le corpus initial est presque toujours trop abondant. Sélectionnez selon quatre
critères, dans cet ordre : la **pertinence** pour le fil conducteur, la
**qualité technique** (netteté, résolution exploitable, état de conservation),
la **valeur documentaire** (lieu, date et sujet identifiables) et la **variété**
(points de vue, échelles, époques). Une belle image hors sujet est hors sujet.

Comptez large puis coupez : pour un livret de 24 pages, une présélection de 60
à 80 images aboutit à 25 ou 30 images publiées.

### 5.2 Formats et cadrages

Chaque image reçoit dans le chemin de fer l'un des cinq formats de la matrice :

| Format | Emprise | Usage |
|--------|---------|-------|
| Pleine ouverture | Deux pages à fond perdu | Panorama, image majeure de chapitre |
| Pleine page | Une page à fond perdu ou dans les marges | Image dominante, respiration |
| Demi-page | La moitié de la surface de composition | Image d'accompagnement du texte |
| Module | Une colonne ou un multiple du module de grille | Mosaïque, série |
| Vignette | Moins d'une demi-colonne | Détail, comparaison, repère |

Le cadrage se décide à la source et se note (recadrage en pourcentage ou
coordonnées), jamais improvisé dans la maquette. Un recadrage ne doit pas
supprimer d'information documentaire (une date sur un mur, une enseigne, un
personnage identifié). Les documents d'archives (cartes postales, plans) sont
reproduits **entiers, avec leurs bords**, sauf mention explicite « détail » dans
la légende.

### 5.3 Orientation

Une image verticale sur un format portrait occupe naturellement la page ; une
image horizontale appelle une demi-page ou une pleine ouverture. Ne tournez
jamais une image pour la faire entrer : on change son format d'emprise, pas son
orientation. Deux images de même sujet et d'époques différentes (avant/après)
sont cadrées identiquement et placées à la même taille, côte à côte ou l'une
sous l'autre.

### 5.4 Qualité et résolution

La règle prépresse est développée dans [PRINT_PIPELINE.md](PRINT_PIPELINE.md) ;
au stade méthodologique, retenez que **la résolution effective détermine
l'emprise maximale**. Une numérisation de 1 800 × 1 200 pixels ne peut pas
dépasser 152 × 102 mm à 300 dpi : c'est une demi-page A5, pas une pleine page
A4. Notez pour chaque image son emprise maximale dès l'inventaire du corpus.

### 5.5 Provenance et droits

Dans un projet patrimonial, chaque image est un document : elle a un
propriétaire, une cote, un auteur parfois, des droits toujours. L'inventaire
du corpus comporte au minimum : identifiant interne, description, lieu, date ou
fourchette, auteur ou éditeur, fonds ou propriétaire, cote, autorisation de
reproduction obtenue (oui/non/en cours), mention à porter en légende.

Les cartes postales éditées avant 1930 sont le plus souvent dans le domaine
public pour l'image, mais l'exemplaire numérisé appartient à une collection
qu'il convient de citer. Les photographies familiales nécessitent l'accord du
détenteur et, pour des personnes identifiables vivantes, leur accord.

### 5.6 Traitement

Le traitement des images d'archives est conservateur : correction du
contraste et de la dominante, dépoussiérage, redressement. On ne « restaure »
pas (pas de suppression d'éléments, pas de colorisation non signalée). Un
traitement lourd est mentionné en légende : « retouche numérique », « colorisé ».
Le traitement se fait sur une copie ; l'original numérisé est archivé intact.

## 6. Légendes

### 6.1 Rôle

Dans une publication patrimoniale, la légende est le texte le plus lu. Elle
n'est pas une description de ce que l'on voit, c'est une information de premier
rang qui répond en une phrase à *où*, *quand*, *quoi*, *d'où vient-ce*. Elle
est rédigée en même temps que le chemin de fer, à partir de l'inventaire.

### 6.2 Structure

La légende MatrixBook comporte quatre éléments, dans cet ordre, séparés par
des points :

```text
[Titre ou sujet]. [Lieu], [date]. [Commentaire éventuel]. [Source]
```

Exemple :

```text
La place de l'église un jour de foire. Le Cruet, vers 1912. Le tilleul
planté en 1848 sera abattu en 1961. Carte postale, éd. Grimal, coll. part.
```

- **Titre ou sujet** : ce que montre l'image, en une proposition nominale.
- **Lieu, date** : le toponyme tel qu'il est écrit aujourd'hui ; la date connue,
  sinon une fourchette (« vers 1912 », « années 1950 »), jamais une date
  inventée.
- **Commentaire** : une information qui ne se voit pas (contexte, devenir,
  identification d'un détail). Une phrase, deux au plus.
- **Source** : nature du document, auteur ou éditeur, fonds et cote. Format
  fixe dans toute la publication.

### 6.3 Longueur et placement

| Format d'image | Longueur cible | Position |
|----------------|----------------|----------|
| Pleine ouverture | 250 à 450 signes | Bas de la page de droite, dans la marge extérieure ou en réserve |
| Pleine page | 150 à 300 signes | Sous l'image ou en marge extérieure |
| Demi-page, module | 80 à 200 signes | Sous l'image, alignée sur son bord gauche |
| Vignette | 40 à 100 signes | Sous ou à côté, alignée |
| Mosaïque | Une légende par image, numérotée | Bloc unique sous la mosaïque |

Une légende est toujours **à moins de 10 mm de son image**, ou reliée par un
numéro sans ambiguïté. Une légende ne chevauche jamais une image, sauf en
réserve sur une pleine ouverture, dans une zone uniforme et sombre ou claire,
et jamais sur un élément documentaire. La légende ne se coupe pas sur deux
pages.

### 6.4 Style

Les légendes sont composées dans le style « Légende » du
[système typographique](TYPOGRAPHY.md#6-légendes) : sans-serif, corps réduit,
alignement à gauche. Le titre ou sujet peut être en gras ou en petites
capitales pour accrocher le regard ; le reste en romain. La source est en
italique ou précédée d'un tiret cadratin selon le choix fait pour toute la
publication.

## 7. Doubles pages

### 7.1 L'unité de lecture

La double page est l'unité de conception. On ne compose jamais une page
seule : ce que le lecteur voit, c'est l'ouverture, avec son pli au milieu. Une
image, un titre ou un blanc se jugent dans l'équilibre des deux pages.

### 7.2 Les six types de composition

MatrixBook réduit le vocabulaire à six types, suffisants pour toute
publication. Chaque double page du chemin de fer en reçoit un.

| Type | Description | Rôle privilégié |
|------|-------------|-----------------|
| Pleine ouverture | Une seule image sur les deux pages, à fond perdu | Ouverture de chapitre, respiration |
| Pleine page + texte | Image à fond perdu sur une page, texte sur l'autre | Ouverture, respiration commentée |
| Asymétrique | Une page en 1/3 texte – 2/3 image (ou l'inverse) | Développement, ouverture de section |
| Texte + image | Texte dominant, une image demi-page ou module | Développement dense |
| Mosaïque | Deux à six images en modules, légendes groupées | Planche, série, comparaison |
| Texte seul | Aucune image, colonnes de texte, éventuellement un exergue | Liminaires, finales, transitions |

Les schémas de chaque type figurent dans
[BOOK_LAYOUT.md](BOOK_LAYOUT.md#8-composition-des-doubles-pages).

### 7.3 Le pli

Le pli est la contrainte majeure de la double page. Rien d'important ne se
place à moins de 8 mm du pli : ni visage, ni texte, ni détail documentaire. Une
image en pleine ouverture est choisie pour supporter le pli : le pli tombe sur
un ciel, un mur, une surface homogène, jamais sur un personnage ou une
inscription. Sur un dos carré collé, le pli « mange » 3 à 5 mm : on ajoute ce
recouvrement à l'image plutôt que de la couper.

### 7.4 Symétrie et tension

Une double page parfaitement symétrique est stable et statique ; elle convient
aux liminaires. Le développement vit de compositions asymétriques dont
l'équilibre vient des masses (une grande image à droite, un bloc de texte et un
blanc à gauche) et non de la géométrie. La règle pratique : le centre de
gravité visuel de l'ouverture doit se situer légèrement au-dessus et à droite du
pli, là où le regard se pose naturellement.

## 8. Équilibre texte / image

### 8.1 Ratios de référence

Le ratio texte/image se fixe pour l'ensemble de la publication, puis se module
double page par double page. Les cibles MatrixBook :

| Type de publication | Texte | Image | Signes par page courante |
|---------------------|-------|-------|--------------------------|
| Carte postale (recto) | 5 % | 95 % | 0 à 60 |
| Livret de visite ou d'exposition | 40 % | 60 % | 1 200 à 1 800 |
| Livret patrimonial | 45 % | 55 % | 1 500 à 2 200 |
| Livre A5 (chronique, recueil) | 60 % | 40 % | 1 800 à 2 400 |
| Beau livre A4 | 25 % | 75 % | 1 500 à 3 000 (deux colonnes) |
| Catalogue, atlas | 20 % | 80 % | 800 à 1 500 |

Le ratio se mesure en surface de composition (hors marges), en cumulant les
doubles pages. Un écart de plus ou moins 10 points par rapport à la cible
appelle une révision du chemin de fer, pas un tassement de la maquette.

### 8.2 Le texte se coupe, l'image ne se réduit pas

Face à un conflit de place, la hiérarchie MatrixBook est la suivante : on
coupe le texte, ou on reporte un paragraphe sur la page suivante ; on ne réduit
pas une image en dessous de son format prévu au chemin de fer, et on ne réduit
jamais le corps ni l'interlignage. Un texte qui doit être coupé de plus de 20 %
signale une erreur de planification : on ajoute une double page.

### 8.3 Le texte au service de l'image, l'image au service du texte

Un texte courant et une image placés sur la même double page doivent se
répondre : le texte évoque ce que l'image montre, ou l'image illustre ce que le
texte raconte. Une image « décorative » sans lien avec le texte voisin brouille
la lecture ; on la déplace ou on la supprime. Inversement, un passage
essentiel sans image appelle au moins une vignette ou un encadré pour ne pas
former un mur de texte.

### 8.4 Le cas de la carte postale

La carte postale inverse la logique du livre : le recto est une image quasi
seule, avec un titre court et un cartouche ; le verso porte la légende
complète, la source et les mentions. C'est le format qui pardonne le moins :
une carte postale patrimoniale mal légendée est un simple objet décoratif. Le
gabarit [postcard](../templates/postcard/README.md) détaille la répartition.

## 9. Liste de contrôle méthodologique

Avant d'ouvrir le logiciel de mise en page :

- [ ] Le fil conducteur tient en une phrase (*quoi*, *à travers quel matériau*, *pour qui*).
- [ ] L'inventaire du corpus indique, pour chaque image, provenance, cote, date, droits et emprise maximale.
- [ ] Le chemin de fer attribue un rôle et un type de composition à chaque double page.
- [ ] Chaque chapitre ouvre sur une double page.
- [ ] Aucune séquence de plus de trois doubles pages denses sans respiration.
- [ ] Le ratio texte/image global est dans la cible de la famille de publication.
- [ ] Les légendes sont rédigées selon la structure sujet – lieu, date – commentaire – source.
- [ ] Les images en pleine ouverture ont été vérifiées au pli.
- [ ] Le nombre de pages est compatible avec la reliure (multiple de 4 pour un livret agrafé, de 8 ou 16 pour un dos carré).

Pendant la maquette :

- [ ] Aucune image en dessous de son emprise prévue ; aucun corps réduit pour « faire rentrer ».
- [ ] Chaque légende est à moins de 10 mm de son image ou numérotée sans ambiguïté.
- [ ] Le point d'entrée de chaque double page est identifiable à un mètre.
- [ ] Le blanc budgété est respecté (20 % en page courante, 50 % en respiration).
- [ ] Les motifs récurrents (cartouches, ouvertures, avant/après) sont identiques d'un chapitre à l'autre.

Ces contrôles sont repris, pour la partie technique, par la liste de
vérification prépresse de [PRINT_PIPELINE.md](PRINT_PIPELINE.md#6-vérification-prépresse).
