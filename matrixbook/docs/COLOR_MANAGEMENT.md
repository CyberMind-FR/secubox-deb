# Gestion de la couleur

Ce guide explique comment MatrixBook gère la couleur de la numérisation à
l'impression : principes des profils ICC, choix entre FOGRA39, FOGRA51 et
FOGRA52, conversion RVB → CMJN, et pièges courants. Il complète la
[chaîne prépresse](PRINT_PIPELINE.md) et alimente les valeurs de la
[palette](DESIGN_SYSTEM.md#2-palette).

## Sommaire

1. [Pourquoi gérer la couleur](#1-pourquoi-gérer-la-couleur)
2. [Profils ICC](#2-profils-icc)
3. [FOGRA39](#3-fogra39)
4. [FOGRA51](#4-fogra51)
5. [FOGRA52 et le papier non couché](#5-fogra52-et-le-papier-non-couché)
6. [Quel profil choisir](#6-quel-profil-choisir)
7. [Conversion RVB → CMJN](#7-conversion-rvb--cmjn)
8. [Écran et épreuvage](#8-écran-et-épreuvage)
9. [Pièges courants](#9-pièges-courants)
10. [Liste de contrôle couleur](#10-liste-de-contrôle-couleur)

## 1. Pourquoi gérer la couleur

Une même valeur numérique n'a pas la même apparence sur un écran, sur un
papier couché brillant et sur un papier offset mat. Sans gestion de la
couleur, un rouge cinabre saisi à l'écran ressort brun sur le tirage, un ciel
bleu vire au violet, un gris neutre prend une dominante. La gestion de la
couleur consiste à décrire chaque périphérique (scanner, écran, presse +
papier) par un **profil ICC** et à laisser les logiciels convertir les valeurs
d'un profil à l'autre en préservant l'apparence autant que la gamme du
périphérique de destination le permet.

Pour une publication patrimoniale, l'enjeu est concret : la fidélité des tons
sépia d'une carte postale, du bleu d'une colorisation ancienne, de la teinte
d'un papier jauni. Ce sont des couleurs subtiles, à faible saturation, que
l'offset reproduit bien **à condition** que la conversion soit maîtrisée.

## 2. Profils ICC

### 2.1 Définition

Un profil ICC est un fichier (`.icc` ou `.icm`) qui décrit la relation entre
les valeurs numériques d'un périphérique (RVB pour un écran, CMJN pour une
presse) et des couleurs mesurées dans un espace indépendant (CIE L\*a\*b\*).
Convertir une image de sRGB vers ISO Coated v2, c'est passer par L\*a\*b\* :
sRGB → L\*a\*b\* → CMJN.

### 2.2 Les trois familles de profils dans un projet MatrixBook

| Famille | Exemples | Rôle |
|---------|----------|------|
| Profils d'entrée | Profil du scanner, profil de l'appareil photo, sRGB ou Adobe RGB incorporé dans l'image | Décrivent ce que signifient les valeurs RVB d'une image source |
| Profils d'affichage | Profil de l'écran, créé par une sonde de calibration | Permettent l'épreuvage à l'écran (soft proofing) |
| Profils de sortie | ISO Coated v2 300 % (FOGRA39), PSO Coated v3 (FOGRA51), PSO Uncoated v3 (FOGRA52) | Décrivent la presse et le papier ; définissent la conversion finale et le TAC |

### 2.3 Caractérisation et profil : FOGRA et ECI

**FOGRA** (institut allemand de recherche pour l'impression) publie des
**données de caractérisation** : des mesures colorimétriques d'une gamme
imprimée dans des conditions normalisées (ISO 12647-2). L'**ECI** (European
Color Initiative) en dérive des **profils ICC** téléchargeables gratuitement.
Ainsi :

| Données de caractérisation | Profil ICC (ECI) | Condition d'impression ISO 12647-2 |
|----------------------------|------------------|------------------------------------|
| FOGRA39 (2006) | ISO Coated v2 (ECI), ISO Coated v2 300 % (ECI) | Papier couché brillant ou mat, type 1 et 2 (ancienne classification) |
| FOGRA51 (2015) | PSO Coated v3 | Papier couché premium, PS1 (nouvelle classification) |
| FOGRA52 (2015) | PSO Uncoated v3 | Papier non couché blanc, PS5 |
| FOGRA47 (2009) | PSO Uncoated ISO12647 (ECI) | Papier non couché blanc, ancienne classification |

Dire « imprimer en FOGRA39 » signifie « selon la condition d'impression
caractérisée par FOGRA39 » ; le fichier qu'on incorpore est le profil ECI
correspondant.

## 3. FOGRA39

| Élément | Valeur |
|---------|--------|
| Profils ECI | ISO Coated v2 (ECI) — TAC 330 % ; **ISO Coated v2 300 % (ECI)** — TAC 300 % |
| Norme | ISO 12647-2:2004, amendement 2007 |
| Papier de référence | Couché brillant ou mat, 115 g/m², blancheur mesurée sans tenir compte des azurants optiques (illuminant D50, mesure M0) |
| Engraissement du point (TVI) | Courbes A (CMJ) et B (K), environ 14 % et 17 % à 40 % |
| Usage | Standard de fait de l'offset feuille sur couché de 2007 à 2017, encore très répandu chez les imprimeurs et dans les flux d'impression numérique |

**Quand l'utiliser** : quand l'imprimeur le demande (la majorité des devis
mentionnent encore « PDF/X avec profil ISO Coated v2 300 % ») ; quand le
papier est un couché standard ; quand on ne sait pas et qu'on veut un
résultat prévisible partout. La variante **300 %** est celle de MatrixBook
par défaut : sa limite d'encrage plus basse évite les problèmes de séchage et
de maculage sur les aplats sombres et convient aussi à l'impression numérique.

**Caractéristiques de rendu** : blanc du papier légèrement chaud (le profil
ne tient pas compte des azurants), noir profond, gamme large dans les rouges
et les bleus.

## 4. FOGRA51

| Élément | Valeur |
|---------|--------|
| Profil ECI | **PSO Coated v3** — TAC 300 % (le profil est construit avec un TAC de 300 % malgré l'ancien usage à 330 %) |
| Norme | ISO 12647-2:2013 |
| Papier de référence | Couché premium (PS1), 115 g/m², blancheur mesurée **avec** les azurants optiques (mesure M1, qui prend en compte la fluorescence sous UV) |
| Engraissement du point | Courbes révisées, uniformes CMJK |
| Usage | Standard actuel de l'offset feuille sur couché ; adopté par les imprimeurs équipés en mesure M1 depuis 2016–2018 |

**Ce qui change par rapport à FOGRA39** : la prise en compte des azurants
optiques rend le blanc du papier plus bleu, donc les hautes lumières sont
converties différemment ; les gris neutres sont recalés ; la gamme est
légèrement plus grande dans les bleus. Une image convertie en FOGRA39 puis
imprimée dans des conditions FOGRA51 paraît un peu chaude et terne ; l'inverse
paraît un peu froide. L'écart est faible sur des images d'archives (peu
saturées) mais visible sur un aplat de couleur d'accent.

**Quand l'utiliser** : quand l'imprimeur travaille en ISO 12647-2:2013 et le
demande (« PSO Coated v3 » sur le devis) ; pour des papiers couchés modernes
très blancs avec azurants. Ne pas l'imposer à un imprimeur qui annonce
FOGRA39 : il reconvertirait, ou imprimerait avec un écart.

## 5. FOGRA52 et le papier non couché

Les publications patrimoniales sont souvent imprimées sur **papier non
couché** (offset, bouffant, recyclé, vergé) pour leur toucher et leur
tenue en lecture. Ce papier absorbe davantage l'encre : le point engraisse
plus, le noir est moins profond, la gamme est nettement plus réduite.

| Élément | Valeur |
|---------|--------|
| Profil ECI | **PSO Uncoated v3 (FOGRA52)** — TAC 300 % |
| Papier de référence | Non couché blanc, avec azurants (PS5), mesure M1 |
| Ancien équivalent | PSO Uncoated ISO12647 (FOGRA47) — TAC 300 %, mesure M0 |
| Rendu | Noir maximal autour de L\* 30 (contre L\* 16 en couché) ; les couleurs saturées sont impossibles ; les teintes claires se lavent |

**Conséquences pour la maquette** :

- Les aplats de couleur d'accent paraissent 10 à 15 % plus clairs et moins
  saturés : prévoir la teinte à 100 % là où l'on aurait mis 80 % sur couché.
- Le noir riche descend à 50 / 40 / 40 / 100 pour rester sous 300 % et
  limiter le maculage.
- Les images sombres perdent du détail dans les ombres : éclaircir légèrement
  les ombres (courbe) avant conversion, ou laisser le profil le faire avec
  l'intention perceptive.
- Les filets de 0,25 pt engraissent ; rester à 0,25 pt mais éviter les
  trames fines dans les filets (un filet à 15 K de 0,25 pt disparaît).
- Un papier **teinté** (ivoire, crème) n'a pas de profil ECI : l'imprimeur
  fournit le sien ou l'on utilise FOGRA52 en sachant que les blancs seront
  ceux du papier.

## 6. Quel profil choisir

```text
 L'imprimeur indique un profil sur le devis ?
 ├── oui ─▶ utiliser exactement celui-là (et le lui redemander en fichier s'il n'est pas un profil ECI standard)
 └── non ─▶ quel papier ?
            ├── couché (brillant, satiné, mat) ─▶ ISO Coated v2 300 % (ECI) — FOGRA39
            │                                     (ou PSO Coated v3 — FOGRA51 si l'imprimeur travaille en M1)
            ├── non couché blanc (offset, bouffant, recyclé blanc) ─▶ PSO Uncoated v3 — FOGRA52
            ├── non couché teinté (ivoire, crème, kraft) ─▶ profil de l'imprimeur, sinon FOGRA52 + épreuve
            └── impression numérique (toner, jet d'encre) ─▶ profil fourni par l'imprimeur,
                                                            sinon ISO Coated v2 300 % (couché) ou FOGRA52 (non couché)
```

Recommandations MatrixBook par gabarit :

| Gabarit | Papier conseillé | Profil par défaut |
|---------|------------------|-------------------|
| Carte postale | Couché mat 350 g/m² | ISO Coated v2 300 % (FOGRA39) |
| Livret agrafé A5 | Intérieur couché mat 135 g/m², couverture 250 g/m² | ISO Coated v2 300 % (FOGRA39) |
| Livre A5 | Non couché bouffant 90 g/m² ou couché mat 115 g/m² | PSO Uncoated v3 (FOGRA52) ou ISO Coated v2 300 % |
| Beau livre A4 | Couché mat 150 à 170 g/m² | PSO Coated v3 (FOGRA51) ou ISO Coated v2 300 % |

## 7. Conversion RVB → CMJN

### 7.1 Où et quand convertir

Dans le flux MatrixBook, la conversion a lieu **à l'export PDF**, par le
logiciel de mise en page, vers le profil de sortie. Elle n'a lieu qu'une fois.
Les images sont livrées à la maquette en RVB avec leur profil incorporé
(Adobe RGB 1998 pour les scans et photographies traitées, sRGB pour le
reste).

La conversion manuelle dans Photoshop, GIMP ou darktable (« Convertir en
profil ») ne se justifie que dans deux cas : une image en niveaux de gris
(convertie une fois pour toutes) ; une image dont on veut contrôler
individuellement le rendu dans les ombres (on la convertit, on ajuste en
CMJN, on la place en CMJN et le logiciel la laisse intacte à l'export).

### 7.2 Intentions de rendu

| Intention | Comportement | Usage MatrixBook |
|-----------|--------------|------------------|
| Perceptive | Compresse toute la gamme source dans la gamme de destination en préservant les relations entre couleurs | Photographies saturées (paysages, colorisations vives), images avec beaucoup de couleurs hors gamme |
| Colorimétrie relative | Conserve les couleurs reproductibles, ramène les couleurs hors gamme à la couleur reproductible la plus proche ; le blanc source devient le blanc du papier | **Défaut** pour les documents d'archives, les images peu saturées, les aplats et les couleurs de la palette |
| Colorimétrie absolue | Comme relative, mais simule aussi le blanc du papier de destination | Épreuvage uniquement (simulation d'un papier sur un autre), jamais pour l'export |
| Saturation | Maximise la saturation au détriment de la fidélité | Jamais (graphiques d'affaires) |

La **compensation du point noir** (BPC) est toujours activée : elle fait
correspondre le noir de la source au noir de la destination et évite des
ombres bouchées.

### 7.3 Ce qui se passe hors gamme

Les couleurs RVB que l'offset ne peut pas reproduire : les bleus purs et
violets saturés (le cyan + magenta ne fait pas le bleu de l'écran), les verts
vifs, les oranges fluorescents, les rouges très lumineux. Une image d'archive
en contient rarement ; une photographie contemporaine d'un ciel de montagne
ou d'un champ de colza en contient beaucoup. L'épreuvage à l'écran
(section [8](#8-écran-et-épreuvage)) avec l'alerte de gamme les montre ;
l'intention perceptive les traite en douceur.

### 7.4 Les couleurs de la palette

Les couleurs du design system sont définies **en CMJN** et ne subissent aucune
conversion à l'export (« conserver les valeurs »). Leurs valeurs RVB dans le
tableau de la palette sont le résultat de la conversion inverse
CMJN → sRGB sous ISO Coated v2 300 %, en colorimétrie relative ; elles servent
à l'écran et aux documents web du projet. Une couleur d'accent saisie en RVB
puis convertie donnerait des valeurs CMJN à quatre encres, moins stables :
c'est pourquoi la palette est CMJN d'abord.

### 7.5 Niveaux de gris

Une image en niveaux de gris destinée à l'encre noire seule est convertie
depuis le RVB en « Niveaux de gris » avec le profil Dot Gain 15 % (couché) ou
20 % (non couché), puis placée telle quelle. À l'export, elle reste sur la
plaque K. Une image RVB « visuellement grise » (photographie noir et blanc
scannée en couleur) convertie en CMJN produit un gris quadri avec des
dominantes : la passer en niveaux de gris d'abord.

## 8. Écran et épreuvage

### 8.1 Calibration

Un écran non calibré est un écran menteur. Calibrer avec une sonde
(colorimètre) :

| Paramètre | Cible pour le prépresse |
|-----------|-------------------------|
| Point blanc | D50 (5 000 K) pour juger l'impression ; D65 acceptable pour le travail courant |
| Luminance | 80 à 120 cd/m² (les écrans sortent d'usine à 250 et plus, beaucoup trop lumineux) |
| Gamma | 2,2 (ou L\* ) |
| Fréquence | Tous les mois, ou à chaque changement d'ambiance lumineuse |

Sans sonde : au minimum, baisser la luminosité de l'écran à environ un tiers,
choisir un point blanc « chaud » dans les réglages système, et ne jamais juger
une couleur sur un écran de portable ou de téléphone.

### 8.2 Épreuvage à l'écran (soft proofing)

InDesign : « Affichage › Format d'épreuve › Personnalisé », profil de
l'imprimeur, « Simuler la couleur du papier » coché, « Conserver les numéros
CMJN » coché. Scribus : « Affichage › Aperçu › Simuler l'imprimante » avec le
profil défini dans les réglages. Photoshop : « Affichage › Format d'épreuve »
puis « Couleurs d'épreuve » et « Alerte de gamme ».

L'épreuve à l'écran montre l'aplatissement des couleurs et la perte de
contraste sur le papier de destination. Elle ne remplace pas l'épreuve
contractuelle.

### 8.3 Épreuve contractuelle

L'épreuve contractuelle (« cromalin » par abus de langage, aujourd'hui une
épreuve jet d'encre certifiée) est produite par l'imprimeur avec le profil de
sortie et vérifiée par une bande de contrôle mesurée (Ugra/FOGRA Media Wedge).
Elle fait foi entre le client et l'imprimeur pour la couleur : le tirage doit
lui correspondre dans les tolérances ISO 12647-7. La demander pour la
couverture et pour deux ou trois doubles pages représentatives (une image
sombre, une image claire, un aplat d'accent). Son coût est faible au regard
d'un tirage raté.

## 9. Pièges courants

| Piège | Symptôme | Cause | Correction |
|-------|----------|-------|------------|
| Double conversion | Images ternes, gris qui virent | Image déjà convertie en CMJN dans un profil, reconvertie dans un autre à l'export | Régler la gestion des couleurs sur « Conserver les valeurs » pour le CMJN ; garder les images en RVB jusqu'à l'export |
| Image sans profil | Rendu différent d'un logiciel à l'autre | Scanner ou logiciel qui n'incorpore pas de profil ; l'image est traitée comme sRGB | Attribuer le bon profil (celui du scanner, ou sRGB / Adobe RGB selon l'origine) avant placement |
| Adobe RGB traité comme sRGB | Image lavée, peu saturée | Profil non incorporé ou logiciel qui l'ignore | Vérifier l'incorporation ; convertir en sRGB si la chaîne aval ne gère pas Adobe RGB |
| Noir RVB | Texte en noir quadri, repérage visible, plaques inutiles | Texte importé de Word ou du web, logo RVB | Appliquer `MB-Noir texte` ; convertir les logos en CMJN |
| Bleu qui vire au violet | Ciels et bleus d'accent violacés | Le bleu RVB est hors gamme ; le magenta domine dans la conversion | Baisser le magenta dans l'aplat (`MB-Bleu ardoise` est conçu pour ça) ; intention perceptive pour les images |
| Vert éteint | Végétation grise | Vert RVB saturé hors gamme | Accepter la perte, ou réduire la saturation à la source ; épreuve |
| Gris à dominante | Gris rosés ou verdâtres selon les pages | Gris quadri au lieu de K seul, ou variation de repérage | Gris en K seul dans la palette ; images noir et blanc en niveaux de gris |
| TAC dépassé | Aplats qui maculent, séchage lent, décalque au verso | Noir saisi à 100 / 100 / 100 / 100 ou image CMJN d'un autre profil | Noir riche 60 / 40 / 40 / 100 ; conversion par profil |
| Écran trop lumineux | Tirage jugé « trop sombre » | Écran à 250 cd/m² au lieu de 100 | Calibrer ; simuler le papier |
| Profil de sortie absent du PDF | L'imprimeur convertit avec son profil par défaut, écarts imprévisibles | Export en PDF générique | Exporter en PDF/X-4 avec Output Intent |
| Azurants optiques | Blancs et pastels différents entre épreuve et tirage | Épreuve en M0 (FOGRA39), tirage sur papier riche en azurants | Choisir FOGRA51/52 si l'imprimeur mesure en M1 ; comparer sous lumière normalisée D50 |
| Papier teinté | Toutes les couleurs décalées vers la teinte du papier | Aucun profil ne décrit le papier | Épreuve sur le papier réel ; réduire les aplats clairs ; accepter le blanc du papier comme blanc |
| Mélange de profils dans un même document | Une page plus chaude que la précédente | Images CMJN de plusieurs provenances (photographe, ancien imprimeur) | Reconvertir vers RVB n'est pas possible sans perte ; demander les RVB d'origine ou harmoniser en CMJN à la main sur épreuve |
| Impression numérique jugée avec un profil offset | Couleurs plus saturées ou plus ternes que prévu | Les presses numériques ont leur propre gamme, souvent plus large que l'offset | Demander le profil de la machine ; sinon ISO Coated v2 300 % et une épreuve sur la machine |

## 10. Liste de contrôle couleur

- [ ] Profil de sortie confirmé par l'imprimeur (nom exact, fichier si non standard).
- [ ] Profils de travail du document réglés (RVB Adobe RGB ou sRGB, CMJN = sortie, gris Dot Gain adapté).
- [ ] Toutes les images RVB ont un profil incorporé ; aucune « non étiquetée ».
- [ ] Les images noir et blanc sont en niveaux de gris, pas en RVB ni CMJN.
- [ ] Les images CMJN fournies par des tiers sont conservées sans reconversion (« Conserver les valeurs »).
- [ ] Le nuancier ne contient que des couleurs CMJN de la palette, plus les tons directs prévus au devis.
- [ ] Intention de rendu : colorimétrie relative avec compensation du point noir par défaut ;
  perceptive pour les photographies saturées.
- [ ] Épreuvage à l'écran activé avec le profil de sortie pour juger les images.
- [ ] Export PDF/X-4 avec conversion vers la destination et Output Intent identique.
- [ ] Épreuve contractuelle demandée pour la couverture et les pages critiques.
