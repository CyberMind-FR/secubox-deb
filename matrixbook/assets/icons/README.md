# Icônes

Jeu de 16 icônes vectorielles au trait, conçues pour les cartouches, encadrés
et légendes MatrixBook. Elles sont dessinées sur une grille de 24 × 24 unités,
trait de 1,5 unité, extrémités et jonctions arrondies, sans remplissage (sauf
les points de la chronologie).

La couleur n'est pas fixée dans les fichiers (`stroke="currentColor"`) : elle
est héritée du contexte, ce qui permet d'appliquer n'importe quelle teinte de la
[palette](../../docs/DESIGN_SYSTEM.md#2-palette) à l'import.

## Inventaire

| Fichier | Nom | Usage recommandé |
|---------|-----|------------------|
| `lieu.svg` | Lieu | Cartouche de localisation, légende avec toponyme |
| `date.svg` | Date | Cartouche de datation, chronologie |
| `source.svg` | Source | Mention de la provenance d'un document |
| `archive.svg` | Archive | Cote d'archives, fonds documentaire |
| `note.svg` | Note | Encadré « Note », complément d'information |
| `repere.svg` | Repère | Encadré « Repère » : définition, contexte |
| `attention.svg` | Attention | Encadré « Attention » : mise en garde, incertitude |
| `oeil.svg` | Regard | Encadré « Regard » : lecture guidée d'une image |
| `carte.svg` | Carte | Renvoi vers une carte, plan de situation |
| `photo.svg` | Photographie | Nature du document : photographie |
| `plan.svg` | Plan | Nature du document : plan, cadastre, relevé |
| `temoin.svg` | Témoignage | Citation orale, témoignage recueilli |
| `fleche.svg` | Renvoi | Renvoi de page (« voir p. 12 ») |
| `chrono.svg` | Chronologie | Frise ou bandeau chronologique |
| `web.svg` | Lien | Ressource en ligne, QR code |
| `avant-apres.svg` | Avant / après | Comparaison de deux états d'un même lieu |

## Règles d'usage

- **Taille minimale à l'impression : 4 mm** (trait ≈ 0,25 mm). En dessous, le
  trait s'empâte en offset et disparaît en numérique.
- **Tailles recommandées :** 4 mm dans une légende, 5 mm dans un cartouche,
  6 mm en tête d'encadré, 8 mm en ouverture de chapitre.
- **Une icône, une fonction.** Ne pas utiliser `lieu` pour autre chose qu'un
  lieu ; la cohérence sémantique fait la lisibilité du système.
- **Alignement :** centrer verticalement l'icône sur la hauteur d'x du texte
  qui l'accompagne, avec un espace de 1 mm (légende) ou 1,5 mm (cartouche).
- **Couleur :** noir texte (K 100) par défaut ; teinte de la palette uniquement
  lorsque l'encadré porte déjà cette teinte (voir la section
  « Encadrés » du [design system](../../docs/DESIGN_SYSTEM.md#6-encadrés)).
- **Ne pas** changer l'épaisseur de trait, ajouter d'ombre ni de dégradé.

## Import

- **InDesign / Affinity :** importer le SVG ; la couleur se pilote ensuite via
  le contour de l'objet ou en convertissant en tracés.
- **Scribus :** « Fichier › Importer › Image vectorielle » ; appliquer la couleur
  de contour souhaitée dans les propriétés.
- **Web ou PDF interactif :** inclure en ligne et définir `color` sur le conteneur.

## Ajouter une icône

1. Dessiner sur 24 × 24, trait 1,5, arrondis, sans remplissage.
2. Nommer le fichier en minuscules sans accent, un tiret entre les mots.
3. Ajouter une balise `<title>` décrivant l'icône.
4. Compléter le tableau ci-dessus et, si nécessaire, la liste des encadrés du
   design system.
