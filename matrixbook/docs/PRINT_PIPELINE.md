# Chaîne prépresse

Ce guide décrit la chaîne de production imprimée MatrixBook, de l'image source
au PDF remis à l'imprimeur : résolution, CMJN, profils ICC, PDF/X-4,
vérification prépresse, contrôle des noirs, transparence et paramètres
d'export pour InDesign et Scribus. La procédure pas-à-pas de remise à
l'imprimeur est dans [EXPORT_GUIDE.md](EXPORT_GUIDE.md) ; le détail des
profils dans [COLOR_MANAGEMENT.md](COLOR_MANAGEMENT.md).

## Sommaire

1. [Vue d'ensemble](#1-vue-densemble)
2. [Résolution : 300 dpi](#2-résolution--300-dpi)
3. [CMJN](#3-cmjn)
4. [Profils ICC](#4-profils-icc)
5. [PDF/X-4](#5-pdfx-4)
6. [Vérification prépresse](#6-vérification-prépresse)
7. [Contrôle des noirs](#7-contrôle-des-noirs)
8. [Transparence](#8-transparence)
9. [Export depuis InDesign](#9-export-depuis-indesign)
10. [Export depuis Scribus](#10-export-depuis-scribus)
11. [Autres logiciels](#11-autres-logiciels)

## 1. Vue d'ensemble

```text
 Sources              Préparation            Mise en page           Export             Contrôle          Imprimeur
 ┌──────────┐   ┌──────────────────┐   ┌──────────────────┐   ┌────────────┐   ┌──────────────┐   ┌──────────┐
 │ scans    │──▶│ traitement       │──▶│ InDesign /       │──▶│ PDF/X-4    │──▶│ préflight    │──▶│ BAT      │
 │ photos   │   │ recadrage        │   │ Scribus /        │   │ profil de  │   │ Acrobat /    │   │ épreuve  │
 │ vecteurs │   │ résolution       │   │ Affinity         │   │ sortie ICC │   │ pdfcpu / gs  │   │ tirage   │
 │ textes   │   │ TIFF / PSD       │   │ styles MB-       │   │ fond perdu │   │ liste §6     │   │          │
 └──────────┘   └──────────────────┘   └──────────────────┘   └────────────┘   └──────────────┘   └──────────┘
   RVB, tel quel   RVB profilé          RVB natif, CMJN pour       conversion à      corrections        aucune
   archivé intact  (Adobe RGB / sRGB)   aplats et texte            l'export          puis ré-export     modification
```

Principe MatrixBook : **les images restent en RVB profilé jusqu'à l'export**,
où le logiciel de mise en page les convertit dans le profil de sortie demandé
par l'imprimeur. Les aplats, filets et textes sont définis en CMJN dès la
maquette. Ce flux (« RVB tardif ») évite les doubles conversions, conserve la
gamme de l'image pour une réimpression sur un autre papier, et laisse le
contrôle des noirs au maquettiste.

Deux exceptions : les images en niveaux de gris, converties en mode
« Niveaux de gris » (une seule encre) dès la préparation ; et les cas où
l'imprimeur exige explicitement des images CMJN dans un profil précis.

## 2. Résolution : 300 dpi

### 2.1 Règle

| Type d'image | Résolution effective minimale | Résolution effective recommandée |
|--------------|-------------------------------|----------------------------------|
| Photographie, document en tons continus (couleur ou niveaux de gris) | 250 ppp | 300 ppp |
| Image au trait (bitmap 1 bit : plan, gravure, texte scanné) | 800 ppp | 1 200 ppp |
| Image de fond peu détaillée (texture, ciel) | 200 ppp | 300 ppp |
| Vecteur (SVG, AI, EPS, PDF) | Sans objet | Sans objet |

La **résolution effective** est celle de l'image à sa taille d'impression,
pas celle inscrite dans le fichier. Une image de 3 000 × 2 000 pixels mesure
254 × 169 mm à 300 ppp ; placée à 127 mm de large, sa résolution effective est
de 600 ppp ; placée à 508 mm, elle tombe à 150 ppp.

```text
 résolution effective (ppp) = largeur en pixels ÷ (largeur imprimée en mm ÷ 25,4)

 exemple : 1 800 px ÷ (152 mm ÷ 25,4) = 1 800 ÷ 5,98 = 301 ppp  ✔
           1 800 px ÷ (210 mm ÷ 25,4) = 1 800 ÷ 8,27 = 218 ppp  ✘ (sauf image de fond)
```

### 2.2 Emprise maximale d'une image

À noter dans l'inventaire du corpus, dès la numérisation :

| Pixels (côté long) | Emprise maximale à 300 ppp | Format MatrixBook compatible |
|--------------------|----------------------------|------------------------------|
| 1 200 px | 102 mm | Vignette, module A5 |
| 1 800 px | 152 mm | Demi-page A5, pleine largeur A5 dans les marges, carte postale |
| 2 500 px | 212 mm | Pleine page A5 à fond perdu (154 × 216 mm), pleine largeur A4 dans les marges |
| 3 600 px | 305 mm | Pleine page A4 à fond perdu (216 × 303 mm), pleine ouverture A5 (302 mm) |
| 5 100 px | 432 mm | Pleine ouverture A4 (426 mm) |

### 2.3 Numérisation

| Document | Résolution de numérisation | Mode | Format |
|----------|----------------------------|------|--------|
| Carte postale 140 × 90 mm | 1 200 ppp (permet une pleine page A4) | Couleur 48 bits ou 24 bits | TIFF non compressé ou LZW |
| Photographie 10 × 15 cm | 800 ppp | Couleur ou niveaux de gris 16 bits | TIFF |
| Négatif ou diapositive 24 × 36 mm | 4 000 ppp | Couleur 48 bits | TIFF |
| Plan A2 ou plus grand | 300 à 400 ppp | Couleur 24 bits | TIFF, ou PDF si numérisé par un prestataire |
| Document au trait (gravure, texte) | 1 200 ppp | Niveaux de gris, puis seuillage en bitmap si nécessaire | TIFF |

Numériser **une fois, à la résolution maximale utile**, et archiver le fichier
brut intact (`SRC_…`). Toutes les versions de travail dérivent de cette source.

### 2.4 Ne jamais rééchantillonner vers le haut

Augmenter la résolution d'une image dans un logiciel n'ajoute aucune
information ; le résultat est flou et présente des artefacts. Une image
insuffisante change d'emprise (voir le tableau ci-dessus) ou n'est pas
publiée. Les outils de « super-résolution » par apprentissage peuvent aider
sur une photographie, jamais sur un document patrimonial dont ils inventent
les détails.

### 2.5 Compression

| Étape | Format | Compression |
|-------|--------|-------------|
| Source archivée | TIFF | Aucune ou LZW (sans perte) |
| Travail | TIFF ou PSD | LZW / ZIP (sans perte) |
| Placement dans la maquette | TIFF, PSD, ou JPEG qualité maximale (12) si la taille l'impose | Sans perte de préférence |
| PDF imprimeur | Images dans le PDF | JPEG qualité maximale ou ZIP ; jamais « JPEG moyenne » ; pas de rééchantillonnage sous 300 ppp |

## 3. CMJN

### 3.1 Ce qui est en CMJN dans la maquette

| Élément | Espace colorimétrique | Valeurs |
|---------|-----------------------|---------|
| Texte | CMJN | 0 / 0 / 0 / 100 (`MB-Noir texte`) |
| Filets | CMJN | Noir 100 K ou gris K seul |
| Aplats et fonds | CMJN | Valeurs de la [palette](DESIGN_SYSTEM.md#2-palette) |
| Icônes vectorielles | CMJN | Noir 100 K ou accent |
| Images en couleur | RVB profilé (Adobe RGB 1998 ou sRGB), converties à l'export | — |
| Images en niveaux de gris | Niveaux de gris avec profil (Dot Gain 15 % ou Gray Gamma 2.2), imprimées sur K seul | — |
| Images CMJN fournies (par un photographe, un autre imprimeur) | CMJN, conservées dans leur profil | Vérifier le taux d'encrage |

### 3.2 Nuancier du document

Le nuancier de la maquette ne contient que les couleurs de la palette
MatrixBook, définies en CMJN, plus le noir et le papier. Les couleurs RVB
créées par erreur (souvent à l'import d'un logo, ou par un copier-coller) sont
supprimées ou converties avant l'export. Une seule couleur RVB dans un aplat
suffit à produire un noir quadrichromique ou une teinte imprévisible.

### 3.3 Tons directs

Les tons directs (Pantone) ne sont utilisés que si le devis prévoit une
cinquième encre ou une impression à deux tons. Sinon, tout ton direct est
converti en CMJN dans le nuancier **avant** l'export (option « Convertir en
quadri » du gestionnaire d'encres), pour éviter une plaque supplémentaire
facturée ou une couleur de remplacement non maîtrisée.

### 3.4 Noir et blanc

Un livre en noir et blanc (ou une partie en noir et blanc) s'imprime sur la
seule encre noire : toutes les images sont en niveaux de gris, tous les gris
en pourcentage de K. Un gris « quadri » (par exemple 40 / 30 / 30 / 10) sur une
page noir et blanc oblige à imprimer la page en quadrichromie et produit des
dominantes. Le nuancier d'un projet noir et blanc n'a pas d'accent.

## 4. Profils ICC

### 4.1 Profils de travail

| Espace | Profil de travail MatrixBook | Justification |
|--------|-------------------------------|---------------|
| RVB | Adobe RGB (1998) pour les scans et photographies traitées ; sRGB IEC61966-2.1 pour les images issues du web ou d'appareils grand public | Adobe RGB couvre mieux les cyans et verts imprimables ; sRGB est accepté tel quel |
| CMJN | Celui exigé par l'imprimeur, sinon **ISO Coated v2 300 % (ECI)** (FOGRA39) pour un papier couché, **PSO Uncoated v3 (FOGRA52)** pour un papier non couché | Voir [COLOR_MANAGEMENT.md](COLOR_MANAGEMENT.md) |
| Niveaux de gris | Dot Gain 15 % (couché) ou Dot Gain 20 % (non couché) | Anticipe l'engraissement du point |

### 4.2 Règles d'incorporation

- Toute image RVB placée dans la maquette **porte un profil incorporé**. Une
  image sans profil est traitée comme sRGB par le logiciel, ce qui est
  souvent faux pour un scan ; on lui attribue explicitement son profil dans
  Photoshop, GIMP ou darktable avant placement.
- Le document de mise en page est configuré avec les profils de travail
  ci-dessus (InDesign : « Édition › Couleurs » ; Scribus : « Fichier › Réglages
  du document › Gestion des couleurs »).
- Les règles de gestion sont « Conserver les profils incorporés » pour le RVB
  et « Conserver les valeurs (ignorer les profils liés) » pour le CMJN : une
  image CMJN livrée par un tiers ne doit pas être reconvertie.
- Le profil de sortie est celui du PDF/X-4 (« Output Intent ») : il est
  déclaré à l'export et s'applique à la conversion des images RVB.

### 4.3 Où trouver les profils

Les profils ECI (ISO Coated v2, PSO Coated v3, PSO Uncoated v3) sont
téléchargeables gratuitement sur le site de l'European Color Initiative
(`eci.org`). Ils s'installent dans le dossier de profils du système
(`/Library/ColorSync/Profiles` sur macOS, `C:\Windows\System32\spool\drivers\color`
sur Windows, `~/.local/share/color/icc` ou `/usr/share/color/icc` sur Linux).

## 5. PDF/X-4

### 5.1 Pourquoi PDF/X-4

| Norme | Année | Transparence | Couches | Profils RVB | Recommandation |
|-------|-------|--------------|---------|-------------|----------------|
| PDF/X-1a:2001 | 2001 | Aplatie à l'export | Non | Non (tout en CMJN) | Uniquement si l'imprimeur l'exige ; risque d'artefacts d'aplatissement |
| PDF/X-3:2002 | 2002 | Aplatie | Non | Oui | Obsolète en pratique |
| **PDF/X-4:2010** | 2010 | **Conservée (native)** | Oui | Oui, avec profil de sortie | **Standard MatrixBook** |

PDF/X-4 conserve la transparence native (pas d'aplatissement, donc pas de
découpage des zones en pavés ni de texte converti en vecteur), autorise les
images RVB profilées converties par le RIP de l'imprimeur, et incorpore le
profil de sortie qui définit la conversion. C'est la norme demandée par la
majorité des imprimeurs européens depuis les années 2010.

### 5.2 Ce qu'impose PDF/X-4

- Toutes les polices incorporées (sous-ensembles admis).
- Un profil de sortie (« Output Intent ») déclaré ; toutes les couleurs
  indépendantes du périphérique sont rapportées à ce profil.
- Boîtes de page définies : TrimBox (format fini), BleedBox (fond perdu),
  MediaBox (support). La TrimBox doit être centrée dans la BleedBox.
- Pas de contenu chiffré, pas de JavaScript, pas de formulaire, pas de
  commentaire, pas de fichier joint actif.
- Métadonnées XMP présentes (titre, version de la norme).

### 5.3 Réglages MatrixBook

| Paramètre | Valeur |
|-----------|--------|
| Norme | PDF/X-4:2010 |
| Compatibilité | Acrobat 7 (PDF 1.6) ou supérieure |
| Pages | Pages simples (jamais « planches »), sauf demande de l'imprimeur pour une couverture à plat |
| Fond perdu | 3 mm, « utiliser les paramètres de fond perdu du document » |
| Traits de coupe | Oui, décalage 3 mm, épaisseur 0,25 pt |
| Autres repères (repères de montage, gammes de couleurs, informations sur la page) | Non, sauf demande |
| Compression des images couleur et niveaux de gris | Sous-échantillonnage bicubique à 300 ppp pour les images au-dessus de 450 ppp ; JPEG qualité maximale ou ZIP |
| Compression des images monochromes (bitmap) | Sous-échantillonnage à 1 200 ppp pour les images au-dessus de 1 800 ppp ; CCITT groupe 4 |
| Conversion des couleurs | « Convertir vers la destination (conserver les valeurs) » |
| Destination | Profil demandé par l'imprimeur (par défaut ISO Coated v2 300 % ECI) |
| Profil de sortie | Identique à la destination |
| Inclure les profils | Inclure les profils des images RVB ; ne pas inclure les profils des images CMJN |
| Polices | Incorporer toutes (sous-ensemble en dessous de 100 %) |
| Calques | Ne pas exporter les calques non imprimables (grilles, notes) |
| Hyperliens, signets, éléments interactifs | Non |

## 6. Vérification prépresse

Le préflight se fait sur le PDF exporté, pas sur le document source : c'est
le fichier que l'imprimeur recevra.

### 6.1 Liste de contrôle

Document :

- [ ] Format de la TrimBox exactement égal au format fini du gabarit.
- [ ] BleedBox = TrimBox + 3 mm de chaque côté ; fond perdu présent sur toutes les pages qui touchent un bord.
- [ ] Nombre de pages correct et multiple attendu par la reliure ; pages dans l'ordre de lecture ; pages blanches présentes.
- [ ] Norme PDF/X-4 déclarée ; profil de sortie correct ; métadonnées présentes.
- [ ] Aucun calque non imprimable exporté (grille, commentaires).

Couleur :

- [ ] Aucune couleur RVB dans les aplats, textes et filets (les images RVB profilées sont admises en X-4).
- [ ] Aucun ton direct non prévu au devis.
- [ ] Texte en noir 100 K seul ; aucun texte en noir quadrichromique.
- [ ] Aplats noirs de grande surface en noir riche (60 / 40 / 40 / 100), pas en K seul.
- [ ] Taux d'encrage maximal (TAC) inférieur ou égal à la limite du profil
  (300 % pour ISO Coated v2 300 %, 330 % pour PSO Coated v3, 300 % pour PSO Uncoated v3).
- [ ] Aucun objet en surimpression non voulu ; le noir 100 K de texte fin en surimpression, les aplats colorés en défonce.

Images :

- [ ] Résolution effective de toutes les images en tons continus ≥ 250 ppp (objectif 300).
- [ ] Résolution effective des images au trait ≥ 800 ppp.
- [ ] Aucune image manquante ou modifiée après placement (liens à jour).
- [ ] Aucune image compressée en JPEG à faible qualité dans le PDF.

Texte :

- [ ] Toutes les polices incorporées ; aucune police manquante ni substituée.
- [ ] Aucun texte hors zone sûre ; aucun texte de moins de 5 pt (limite de lisibilité, 6 pt en réserve).
- [ ] Filets ≥ 0,25 pt ; filets en réserve ≥ 0,5 pt.
- [ ] Aucun texte en débordement (texte masqué non exporté).

Transparence :

- [ ] Aucun aplatissement forcé ; les objets transparents sont dans l'espace de fusion CMJN du document.
- [ ] Aucune ombre ni dégradé (interdits par le design system).

### 6.2 Outils

| Outil | Licence | Ce qu'il vérifie |
|-------|---------|------------------|
| Acrobat Pro, « Outils › Impression › Contrôle en amont », profil « Conformité PDF/X-4 » puis « Aperçu de la sortie » | Commercial | Conformité X-4, TAC, séparations, résolutions, polices, boîtes de page |
| PDF-XChange Editor, PitStop (plugin Acrobat) | Commercial | Idem, PitStop corrige aussi |
| `pdfcpu validate` et `pdfcpu info` | Libre (Apache 2.0) | Validité structurelle, boîtes de page, polices, images et leurs résolutions |
| Ghostscript (`gs -sDEVICE=inkcov`) | Libre (AGPL) | Couverture d'encre moyenne par page (indique un noir quadri ou un TAC excessif) |
| `pdffonts`, `pdfimages -list` (poppler-utils) | Libre (GPL) | Polices incorporées ; liste des images avec taille en pixels et résolution effective |
| `exiftool` | Libre | Métadonnées XMP, norme PDF/X déclarée, profil de sortie |
| Scribus, « Vérificateur » (avant export) | Libre (GPL) | Images basse résolution, textes en débordement, objets hors page, couleurs RVB, transparence selon la norme choisie |

Exemple de vérification en ligne de commande, sans outil commercial :

```bash
# Polices : toutes doivent être « emb yes »
pdffonts MB_le-cruet_livret-a5_interieur_v03_X4.pdf

# Images : la colonne « x-ppi » / « y-ppi » donne la résolution effective
pdfimages -list MB_le-cruet_livret-a5_interieur_v03_X4.pdf

# Norme et profil de sortie déclarés
exiftool -PDFXVersion -OutputIntent* MB_le-cruet_livret-a5_interieur_v03_X4.pdf

# Boîtes de page (TrimBox, BleedBox) et validité structurelle
pdfcpu info MB_le-cruet_livret-a5_interieur_v03_X4.pdf
pdfcpu validate -mode strict MB_le-cruet_livret-a5_interieur_v03_X4.pdf

# Couverture d'encre par page (C M J N, valeurs entre 0 et 1) :
# un texte noir seul donne ~0 0 0 x ; un noir quadri donne 4 valeurs non nulles
gs -q -o - -sDEVICE=inkcov MB_le-cruet_livret-a5_interieur_v03_X4.pdf
```

### 6.3 Épreuve

Avant le bon à tirer, imprimer le PDF **à 100 %** sur une imprimante de bureau,
avec traits de coupe, et plier ou assembler une maquette en blanc : c'est le
seul moyen de vérifier le rythme, le pli, la lisibilité des corps et
l'emplacement des folios. Pour la couleur, seule une **épreuve contractuelle**
(épreuve certifiée FOGRA fournie par l'imprimeur) fait foi ; l'écran et
l'imprimante de bureau ne sont pas des références.

## 7. Contrôle des noirs

### 7.1 Les quatre noirs

| Noir | Composition | Usage | Interdit pour |
|------|-------------|-------|---------------|
| Noir texte | 0 / 0 / 0 / 100 | Texte, filets, icônes, petits éléments | Aplats de plus de 20 × 20 mm (paraît gris et irrégulier) |
| Noir riche | 60 / 40 / 40 / 100 (TAC 240 %) | Aplats, fonds de couverture, fonds de planche | Texte (repérage impossible sur les lettres fines), filets |
| Noir quadri « accidentel » | Valeurs variables, par exemple 75 / 68 / 67 / 90 (conversion d'un noir RVB) | Aucun | Tout ; à corriger systématiquement en noir texte ou noir riche |
| Noir de repérage | 100 / 100 / 100 / 100 | Traits de coupe et repères générés par le logiciel | Tout contenu de page |

Le noir quadri accidentel est le défaut prépresse le plus fréquent : il vient
d'un texte importé de Word (RVB 0, 0, 0), d'un logo en RVB ou d'un SVG sans
couleur définie. Il se repère dans « Aperçu de la sortie » (Acrobat) en
isolant la plaque K : un texte qui reste visible sur les plaques C, M ou J est
en noir quadri.

### 7.2 Surimpression

- Le noir texte (100 K) est en **surimpression** sur les fonds colorés :
  cela évite un liseré blanc au moindre décalage de repérage. InDesign le fait
  par défaut (« Surimpression du noir à 100 % ») ; Scribus demande de cocher
  « Surimpression » dans les propriétés du texte ou d'activer l'option
  globale à l'export.
- Le noir riche est en **défonce** (le fond est évidé dessous), sinon les
  quatre encres du noir se superposent au fond et dépassent le TAC.
- Les couleurs d'accent sont en défonce. Un texte en couleur fine (moins de
  10 pt) sur fond coloré est à éviter : les décalages de repérage se voient.
- Le texte en **réserve** (blanc) sur noir riche ou sur accent 100 % est en
  corps ≥ 8 pt, graisse Regular ou plus, jamais en Light ni en italique fin.

### 7.3 Taux d'encrage

| Profil | TAC maximal | Noir riche recommandé |
|--------|-------------|-----------------------|
| ISO Coated v2 300 % (FOGRA39) | 300 % | 60 / 40 / 40 / 100 |
| PSO Coated v3 (FOGRA51) | 330 % | 60 / 40 / 40 / 100 (ou 70 / 50 / 50 / 100 si l'imprimeur l'accepte) |
| PSO Uncoated v3 (FOGRA52) | 300 % | 50 / 40 / 40 / 100 |
| Impression numérique (toner) | Souvent 260 à 280 % : vérifier | 40 / 30 / 30 / 100 |

Une image RVB très sombre convertie à l'export ne dépasse jamais le TAC du
profil : c'est l'intérêt de la conversion par profil. Un aplat CMJN saisi à la
main (par exemple 100 / 100 / 100 / 100) le dépasse toujours ; il est refusé
au préflight.

### 7.4 Gris

Les gris de la palette sont des pourcentages de K seul (`MB-Gris pierre` =
60 K, `MB-Gris brume` = 15 K). Un gris quadri (par exemple 30 / 22 / 22 / 0)
produit des dominantes visibles sur un tirage ; il n'est utilisé que si le
projet demande explicitement un gris chaud ou froid, et alors partout.

## 8. Transparence

### 8.1 Position MatrixBook

Le design system n'autorise ni ombre, ni dégradé, ni effet ; la transparence
se limite aux **teintes** (pourcentage d'une couleur, qui n'est pas une
transparence au sens PDF) et à d'éventuelles **opacités d'objet** (un aplat
de parchemin à 80 % sur une image, pour poser un cartouche). PDF/X-4 conserve
ces opacités sans aplatissement.

### 8.2 Réglages

- **Espace de fusion des transparences : CMJN** (InDesign : « Édition ›
  Espace de fusion des transparences › CMJN document »). Un espace de fusion
  RVB produit des couleurs différentes à l'écran et à l'impression sur les
  zones de recouvrement.
- **Aucun aplatissement à l'export** en PDF/X-4. Si l'imprimeur exige
  PDF/X-1a, l'aplatissement se fait avec le préréglage « Haute résolution »
  (rastérisation à 300 ppp minimum, traits à 1 200 ppp, texte et vecteurs
  conservés en vecteurs) et le PDF est contrôlé page par page pour repérer les
  pavés et les textes passés en contours.
- **Tons directs et transparence** ne se mélangent pas : un ton direct sous
  un objet transparent donne un résultat imprévisible ; convertir le ton
  direct en quadri.
- **Texte et transparence** : un texte 100 K en surimpression posé sur un
  objet transparent peut être « aplati » en vecteur par certains RIP ; placer
  les textes sur un calque **au-dessus** de tous les objets transparents.

### 8.3 Ce qui déclenche une transparence sans qu'on le veuille

Les images PSD ou PNG avec couche alpha, les modes de fusion (« Produit »,
« Multiplier ») appliqués à une image, les opacités partielles sur un bloc, les
ombres et contours progressifs. Le préflight Acrobat (« Aperçu de
l'aplatissement ») surligne les objets concernés ; un document MatrixBook
conforme n'en montre presque aucun.

## 9. Export depuis InDesign

### 9.1 Préparation du document

1. « Édition › Couleurs » : RVB Adobe RGB (1998), CMJN selon l'imprimeur
   (par défaut ISO Coated v2 300 % ECI), règles « Conserver les profils
   incorporés » (RVB) et « Conserver les valeurs (ignorer les profils liés) »
   (CMJN), « Demander avant » pour les différences de profil.
2. « Édition › Espace de fusion des transparences › CMJN document ».
3. « Fenêtre › Sortie › Contrôle en amont » : créer un profil MatrixBook qui
   signale les couleurs RVB dans les aplats, la résolution des images sous
   250 ppp, les textes en débordement, les polices manquantes, les tons directs,
   le texte de moins de 5 pt, les filets de moins de 0,25 pt.
4. « Fenêtre › Liens » : tous les liens à jour, aucune image manquante.
5. « Fenêtre › Sortie › Aperçu de la séparation » : vérifier les plaques et
   les limites d'encrage (« Limite d'encre » à 300 % : les zones en
   dépassement s'affichent en rouge).
6. Masquer ou supprimer les calques non imprimables (grille SVG, notes).

### 9.2 Export

« Fichier › Exporter › Adobe PDF (impression) », puis :

| Panneau | Réglage |
|---------|---------|
| Général | Préréglage « [PDF/X-4:2008] » comme base ; Pages : « Toutes », « Pages » (pas « Planches ») ; Exporter les calques : « Calques visibles et imprimables » |
| Compression | Images couleur et gris : bicubique à 300 ppp pour les images au-dessus de 450 ppp, JPEG qualité « Maximum » ou ZIP ; images monochromes : bicubique à 1 200 ppp au-dessus de 1 800 ppp, CCITT groupe 4 ; « Compresser le texte et les dessins au trait » coché ; « Recadrer les données d'image selon les blocs » coché |
| Repères et fonds perdus | Traits de coupe : oui, épaisseur 0,25 pt, décalage 3 mm ; autres repères : non ; Fond perdu : « Utiliser les paramètres de fond perdu du document » (3 mm) ; Zone de ligne-bloc : non |
| Sortie | Conversion des couleurs : « Convertir vers la destination (conserver les valeurs) » ; Destination : le profil de l'imprimeur ; Inclusion des profils : « Inclure les profils source à étiquette » ; Profil de sortie (PDF/X) : identique à la destination ; Gestionnaire d'encres : tous les tons directs convertis en quadri |
| Avancé | Sous-ensemble de polices : 100 % ; Prise en charge OPI : aucune ; Aplatissement des transparences : grisé en X-4 (normal) |
| Sécurité | Aucune |

Enregistrer ces réglages comme préréglage « MatrixBook X-4 » (« Enregistrer le
préréglage… ») pour les réutiliser.

### 9.3 Couverture

La couverture d'un dos carré collé s'exporte séparément, en **une seule page à
plat** (C4 + dos + C1, avec le fond perdu), depuis un document dédié dont la
largeur est 2 × largeur + épaisseur du dos (fournie par l'imprimeur selon le
nombre de pages et le papier). Pour un livret agrafé, la couverture est
exportée en 4 pages simples comme l'intérieur, sauf demande contraire.

## 10. Export depuis Scribus

Scribus 1.6 (ou 1.5.8 et plus) exporte en PDF/X-4 avec conservation de la
transparence et conversion par profil.

### 10.1 Préparation du document

1. « Fichier › Réglages du document › Gestion des couleurs » : activer la
   gestion des couleurs ; profil RVB « Adobe RGB (1998) » (ou sRGB) ; profil
   CMJN celui de l'imprimeur ; profil de l'imprimante identique ; intention
   de rendu « Colorimétrie relative » pour les images et « Colorimétrie
   relative » pour les couleurs unies ; « Compensation du point noir » cochée.
2. « Fichier › Réglages du document › Document » : format fini, « Pages en
   vis-à-vis », marges du gabarit, fond perdu 3 mm sur les quatre côtés.
3. « Fichier › Réglages du document › Guides » : grille de ligne de base 13 pt
   avec décalage égal à la marge de tête.
4. « Édition › Couleurs et fonds » : supprimer les couleurs inutilisées,
   vérifier que toutes les couleurs sont en CMJN (icône) et que « Noir » est
   0 / 0 / 0 / 100.
5. « Fichier › Préférences › Vérificateur » : créer un profil « MatrixBook »
   qui contrôle : résolution des images (minimum 250 ppp, maximum 1 200 ppp),
   textes en débordement, objets hors page, polices non incorporables, couleurs
   RVB (« Vérifier les images couleur RVB » décoché si les images restent en
   RVB profilé), transparence (décoché pour X-4), aplats non conformes.
6. « Fenêtre › Vérificateur » : lancer et corriger jusqu'à « Aucun problème ».

### 10.2 Export

« Fichier › Exporter › Enregistrer en PDF », puis :

| Onglet | Réglage |
|--------|---------|
| Général | Compatibilité : « PDF/X-4 » ; Reliure : gauche ; Exporter toutes les pages, « Pages » (pas « Planches ») ; Compression du texte et des vecteurs cochée ; Méthode de compression des images : « Automatique » ou « Sans perte » ; Qualité : « Maximale » ; Résolution maximale des images : 300 ppp cochée ; « Incorporer le PDF et EPS » coché |
| Polices | Toutes les polices dans « Polices à incorporer » (pas « à vectoriser ») |
| Extras | Rien (les options de présentation sont pour l'écran) |
| Visionneur | Rien |
| Sécurité | Rien |
| Couleur | Sortie destinée à : « Imprimante » ; « Utiliser un profil de gestion des couleurs personnalisé » décoché ; Images : « Utiliser le profil ICC de l'image » coché ; profil du périphérique : celui de l'imprimeur ; intention « Colorimétrie relative » ; Couleurs unies : profil identique, intention « Colorimétrie relative » ; « Convertir les tons directs en couleurs de processus » coché |
| Prépresse | Traits de coupe : coché, décalage 3 mm ; Repères de fond perdu : coché ; Repères de montage et gammes de couleurs : décochés ; Fonds perdus : « Utiliser les fonds perdus du document » ; « Zones de coupe » coché ; Informations PDF/X : titre du document et profil de sortie (« Output Intent ») = profil de l'imprimeur |

Le vérificateur se relance automatiquement avant l'export : ne pas ignorer ses
avertissements.

### 10.3 Limites connues

- Scribus n'applique pas la surimpression du noir automatiquement : la cocher
  objet par objet (« Propriétés › Couleurs › Surimpression ») pour les textes
  100 K sur fond coloré, ou demander à l'imprimeur d'appliquer la surimpression
  du noir au RIP (pratique courante).
- Les images PSD à calques sont aplaties à l'import ; préférer le TIFF.
- La couverture à plat d'un dos carré collé se compose dans un document
  séparé dont la largeur inclut le dos.

## 11. Autres logiciels

| Logiciel | PDF/X-4 | Remarques |
|----------|---------|-----------|
| Affinity Publisher 2 | Oui (« Exporter › PDF (impression) », préréglage PDF/X-4) | Régler le profil de document en CMJN imprimeur ; surimpression du noir dans les préférences ; fond perdu dans « Fichier › Configuration de la planche » |
| QuarkXPress | Oui | Flux comparable à InDesign ; vérifier « Job Jackets » |
| LaTeX (pdfx, memoir) | Oui avec le paquet `pdfx` en mode `x-4` | Adapté aux livres texte ; les images CMJN doivent être préparées en amont ; fond perdu via `geometry` et `crop` |
| LibreOffice, Word, Canva | Non (PDF/A ou PDF générique, images sRGB, noir quadri) | Inadaptés à l'impression professionnelle en quadrichromie ; acceptables pour une épreuve de relecture uniquement |

Quel que soit l'outil, le PDF final passe par la liste de contrôle de la
section [6](#6-vérification-prépresse).
