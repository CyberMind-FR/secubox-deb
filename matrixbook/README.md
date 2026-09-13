# MatrixBook

> Framework éditorial open source pour la création de livres illustrés, de livrets,
> de cartes postales et de publications patrimoniales.

MatrixBook n'est pas un exemple de projet : c'est une **méthode complète**, un
**design system** et une **chaîne de production imprimée** documentés de bout en
bout, prêts à être utilisés par un auteur, une association patrimoniale, un
service d'archives, une collectivité ou un studio graphique.

Tout part d'une idée simple : la **matrice**. Chaque format (carte postale, A5,
A4, livret agrafé) dérive d'une même grille modulaire, d'une même échelle
typographique et d'une même palette. On conçoit une fois, on décline partout.

## Sommaire

- [Présentation](#présentation)
- [Philosophie](#philosophie)
- [Fonctionnalités](#fonctionnalités)
- [Arborescence](#arborescence)
- [Démarrage rapide](#démarrage-rapide)
- [Documentation](#documentation)
- [Gabarits](#gabarits)
- [Feuille de route](#feuille-de-route)
- [Contribuer](#contribuer)
- [Licence](#licence)

## Présentation

MatrixBook répond à un besoin récurrent des projets éditoriaux locaux et
patrimoniaux : des fonds iconographiques riches (cartes postales anciennes,
photographies d'archives, plans, gravures), une vraie volonté de transmettre,
mais peu de repères sur **comment construire un objet imprimé qui tienne la
route**, de la première double page jusqu'au fichier remis à l'imprimeur.

Le framework couvre quatre familles d'objets :

| Objet | Format de référence | Usage typique |
|-------|---------------------|---------------|
| Carte postale | 148 × 105 mm | Diffusion, souvenir, série thématique |
| Livret A5 | 148 × 210 mm, agrafé | Exposition, parcours, monographie courte |
| Livre A5 | 148 × 210 mm, dos carré collé | Recueil, chronique, catalogue |
| Livre A4 | 210 × 297 mm | Beau livre, atlas, fonds photographique |

Chaque objet est décrit par un gabarit (dimensions, marges, fond perdu, zone
sûre, papier, reliure) et s'appuie sur les mêmes guides de conception.

## Philosophie

1. **La matrice avant la page.** On ne dessine pas des pages, on définit une
   grille, une échelle et un rythme ; les pages en découlent.
2. **Le document est un récit.** Une publication illustrée se lit comme une
   séquence : ouverture, développement, respirations, clôture. La mise en page
   sert la narration, jamais l'inverse.
3. **L'image est une source.** Dans un projet patrimonial, chaque illustration a
   une provenance, une date, un lieu. La légende n'est pas un ornement, c'est une
   information de premier rang.
4. **L'impression est la vérité.** Tout ce qui est conçu doit sortir correctement
   d'une presse offset ou numérique : 300 dpi, CMJN, profils ICC, PDF/X-4, noirs
   maîtrisés. Pas de « ça se verra à l'écran ».
5. **Ouvert et pérenne.** Tout est en Markdown UTF-8, versionné, lisible sans
   logiciel propriétaire. Les gabarits sont décrits en valeurs, pas seulement en
   fichiers binaires.

## Fonctionnalités

- **Méthodologie éditoriale** complète : narration visuelle, hiérarchie des pages,
  rythme, illustrations, légendes, doubles pages, équilibre texte/image.
- **Système typographique** : échelle H1 à H6, corps de texte, citations, notes,
  légendes, grille de ligne de base, conventions typographiques françaises.
- **Grilles de mise en page** : marges, colonnes, gouttières, fond perdu, zone
  sûre, pagination, foliotage, composition des doubles pages, avec schémas.
- **Design system** : palette CMJN/RVB, styles nommés, icônes, cartouches,
  encadrés, appels de note, conventions graphiques.
- **Chaîne prépresse professionnelle** : résolution, CMJN, ICC, PDF/X-4,
  vérification, contrôle des noirs, transparence, export InDesign et Scribus.
- **Gestion de la couleur** : FOGRA39, FOGRA51, FOGRA52, conversion RVB → CMJN,
  pièges courants.
- **Guide d'export pas-à-pas** vers l'imprimeur, avec nomenclature de fichiers et
  bon à tirer.
- **Gabarits imprimables** : carte postale, A5, A4, livret agrafé A5.
- **Ressources** : grilles SVG à l'échelle, jeu d'icônes, exemple de chemin de fer.
- **Qualité automatisée** : validation Markdown et vérification des liens en CI,
  modèles d'issues et de pull request.

## Arborescence

```text
matrixbook/
│
├── README.md                     ← ce fichier
├── LICENSE                       ← licence MIT
├── .gitignore
├── .markdownlint.yml             ← règles de validation Markdown
│
├── docs/
│   ├── MATRIXBOOK_DESIGN.md      ← méthodologie éditoriale
│   ├── TYPOGRAPHY.md             ← système typographique
│   ├── BOOK_LAYOUT.md            ← grilles, marges, pagination
│   ├── DESIGN_SYSTEM.md          ← palette, styles, icônes, cartouches
│   ├── PRINT_PIPELINE.md         ← chaîne prépresse
│   ├── COLOR_MANAGEMENT.md       ← profils ICC et conversions
│   └── EXPORT_GUIDE.md           ← export pas-à-pas vers l'imprimeur
│
├── templates/
│   ├── postcard/README.md        ← carte postale 148 × 105 mm
│   ├── a5/README.md              ← A5 portrait
│   ├── a4/README.md              ← A4 portrait
│   └── booklet/README.md         ← livret agrafé A5
│
├── assets/
│   ├── examples/                 ← chemin de fer d'exemple
│   ├── grids/                    ← grilles SVG à l'échelle
│   └── icons/                    ← jeu d'icônes SVG
│
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature.md
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        └── markdown.yml          ← validation Markdown + liens
```

## Démarrage rapide

### 1. Récupérer le framework

```bash
git clone https://github.com/gkerma/matrixbook.git
cd matrixbook
```

### 2. Choisir un gabarit

Ouvrez le README du format visé et relevez ses valeurs (format, marges, fond
perdu, zone sûre, colonnes) :

- [Carte postale](templates/postcard/README.md)
- [A5 portrait](templates/a5/README.md)
- [A4 portrait](templates/a4/README.md)
- [Livret agrafé A5](templates/booklet/README.md)

### 3. Construire le chemin de fer

Avant d'ouvrir un logiciel de mise en page, listez les doubles pages et le rôle
de chacune en suivant la [méthodologie](docs/MATRIXBOOK_DESIGN.md). Un exemple
complet est fourni dans [`assets/examples/`](assets/examples/README.md).

### 4. Créer le document

Dans InDesign, Scribus ou Affinity Publisher :

1. créez le document aux dimensions du gabarit, avec le fond perdu indiqué ;
2. définissez les marges et les colonnes du gabarit ;
3. activez la grille de ligne de base décrite dans [TYPOGRAPHY.md](docs/TYPOGRAPHY.md) ;
4. importez les styles du [design system](docs/DESIGN_SYSTEM.md) ;
5. affichez, si utile, la grille SVG correspondante depuis [`assets/grids/`](assets/grids/README.md).

### 5. Produire et exporter

Suivez [PRINT_PIPELINE.md](docs/PRINT_PIPELINE.md) pour préparer les images et
les couleurs, puis [EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md) pour générer et
vérifier le PDF/X-4 destiné à l'imprimeur.

### 6. Valider les fichiers Markdown (contributeurs)

```bash
npx --yes markdownlint-cli2 "**/*.md"
```

## Documentation

| Guide | Contenu | Lecture |
|-------|---------|---------|
| [MATRIXBOOK_DESIGN.md](docs/MATRIXBOOK_DESIGN.md) | Méthodologie : narration visuelle, hiérarchie, rythme, illustrations, légendes, doubles pages, équilibre texte/image | En premier |
| [TYPOGRAPHY.md](docs/TYPOGRAPHY.md) | Échelle H1–H6, corps, citations, notes, légendes, espacements, grille typographique | Avant la composition |
| [BOOK_LAYOUT.md](docs/BOOK_LAYOUT.md) | Marges, colonnes, gouttières, fond perdu, zone sûre, pagination, foliotage, doubles pages | Avant la composition |
| [DESIGN_SYSTEM.md](docs/DESIGN_SYSTEM.md) | Palette, styles, icônes, cartouches, encadrés, appels de note, conventions | Pendant la composition |
| [PRINT_PIPELINE.md](docs/PRINT_PIPELINE.md) | 300 dpi, CMJN, ICC, PDF/X-4, prépresse, noirs, transparence, InDesign / Scribus | Avant l'export |
| [COLOR_MANAGEMENT.md](docs/COLOR_MANAGEMENT.md) | Profils ICC, FOGRA39, FOGRA51, conversion RVB → CMJN, pièges | Avant l'export |
| [EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md) | Procédure pas-à-pas de remise à l'imprimeur | À l'export |

## Gabarits

| Gabarit | Format fini | Fond perdu | Reliure | Fiche |
|---------|-------------|------------|---------|-------|
| Carte postale | 148 × 105 mm | 3 mm | Aucune | [templates/postcard](templates/postcard/README.md) |
| A5 portrait | 148 × 210 mm | 3 mm | Dos carré collé | [templates/a5](templates/a5/README.md) |
| A4 portrait | 210 × 297 mm | 3 mm | Dos carré collé ou cousu | [templates/a4](templates/a4/README.md) |
| Livret agrafé A5 | 148 × 210 mm | 3 mm | Piqûre à cheval (2 agrafes) | [templates/booklet](templates/booklet/README.md) |

## Feuille de route

### Version 1.0 — Socle (cette version)

- [x] Méthodologie éditoriale complète
- [x] Système typographique et grilles de mise en page
- [x] Design system (palette, styles, icônes, cartouches, encadrés)
- [x] Chaîne prépresse, gestion de la couleur et guide d'export
- [x] Gabarits carte postale, A5, A4, livret agrafé A5
- [x] Validation Markdown et liens en intégration continue

### Version 1.1 — Fichiers natifs

- [ ] Gabarits Scribus (`.sla`) pour les quatre formats
- [ ] Gabarits InDesign (`.idml`) pour les quatre formats
- [ ] Bibliothèque de styles importable (paragraphe, caractère, objet)
- [ ] Nuancier `.ase` de la palette

### Version 1.2 — Formats complémentaires

- [ ] Carte postale panoramique 210 × 100 mm
- [ ] Format carré 210 × 210 mm
- [ ] Marque-page et carte de vœux
- [ ] Dépliant 3 volets A4

### Version 2.0 — Automatisation

- [ ] Génération de chemin de fer depuis un fichier CSV ou YAML
- [ ] Script de vérification de résolution effective des images
- [ ] Préflight automatique du PDF (profil, fond perdu, noirs, taux d'encrage)
- [ ] Génération de légendes depuis les métadonnées IPTC / XMP

Les propositions passent par les [issues](https://github.com/gkerma/matrixbook/issues)
en utilisant les modèles fournis.

## Contribuer

1. Ouvrez une issue (bug ou fonctionnalité) avec le modèle adapté.
2. Créez une branche depuis `main`.
3. Respectez les règles Markdown (`.markdownlint.yml`) et vérifiez les liens.
4. Ouvrez une pull request en complétant la liste de contrôle.

Toute contribution doit rester cohérente avec la matrice : un nouveau format
dérive de la grille de base, un nouveau style s'inscrit dans l'échelle
typographique, une nouvelle couleur reçoit ses valeurs CMJN et RVB.

## Licence

MatrixBook est publié sous licence [MIT](LICENSE). Vous pouvez l'utiliser,
le modifier et le redistribuer librement, y compris dans un cadre commercial,
en conservant la mention de licence.

Les images, textes et documents d'archives que vous placez dans vos propres
publications restent soumis à leurs droits respectifs : vérifiez toujours la
provenance et les autorisations de reproduction (voir la section
« Illustrations » de la [méthodologie](docs/MATRIXBOOK_DESIGN.md#5-illustrations)).
