## Objet de la pull request

Décrivez en quelques lignes ce que change cette pull request et pourquoi.

Issue liée : Closes #

## Type de changement

- [ ] Correction de documentation (valeur, formulation, lien)
- [ ] Nouveau guide ou nouvelle section
- [ ] Nouveau gabarit ou modification d'un gabarit existant
- [ ] Ressource (grille, icône, exemple)
- [ ] Intégration continue, outillage
- [ ] Autre :

## Liste de contrôle qualité

### Contenu

- [ ] Rédigé en français, en Markdown UTF-8, sans texte de remplissage ni section vide.
- [ ] Les valeurs techniques (dimensions, marges, corps, profils) sont cohérentes avec la matrice
  et avec les autres documents qui les reprennent.
- [ ] Toute valeur nouvelle ou modifiée est reportée partout où elle apparaît
  (README, guide, fiche de gabarit, grille SVG, exemple).
- [ ] Les conventions typographiques françaises sont respectées (espaces insécables, guillemets « », capitales accentuées).
- [ ] Aucune image, aucun texte soumis à des droits de tiers n'est ajouté sans mention de licence.

### Structure

- [ ] Un seul H1 par fichier ; hiérarchie des titres continue (pas de saut de niveau).
- [ ] Les nouveaux fichiers sont référencés depuis le README ou le document parent.
- [ ] Les tableaux ont une ligne d'en-tête et des colonnes alignées.
- [ ] Les schémas ASCII sont dans des blocs de code `text`.

### Validation

- [ ] `npx --yes markdownlint-cli2 "**/*.md"` ne remonte aucune erreur.
- [ ] `python3 .github/scripts/check-links.py` ne remonte aucune erreur (liens relatifs et ancres).
- [ ] Les liens externes ajoutés ont été ouverts et vérifiés manuellement.
- [ ] Les fichiers SVG ajoutés ou modifiés s'ouvrent dans un navigateur et respectent l'échelle 1 unité = 1 mm.

### Impression réelle (si un gabarit ou une valeur prépresse change)

- [ ] Fond perdu 3 mm et zone sûre 5 mm (6 mm en A4) respectés.
- [ ] Nombre de pages compatible avec la reliure indiquée.
- [ ] Résolution, profil ICC et norme PDF/X-4 conformes aux guides.
- [ ] Une épreuve de bureau à 100 % a été réalisée pour un nouveau gabarit.

## Commits

- [ ] Commits atomiques avec un message au format `type: description` (`feat`, `docs`, `fix`, `ci`, `chore`).
- [ ] Aucun fichier binaire de travail (PDF, INDD, PSD) n'est ajouté.
