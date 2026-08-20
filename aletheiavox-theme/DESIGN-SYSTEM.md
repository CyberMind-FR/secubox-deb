<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# AletheiaVox — Référence du Design System

La source de vérité des valeurs est `css/tokens.css` ; la source de vérité du
rendu est `demo/index.html`. Ce document explique, il ne remplace pas.

---

## 1. Couleurs

### Palette de base (thème clair)

| Jeton               | Hex       | Rôle                                        |
|---------------------|-----------|---------------------------------------------|
| `--av-white`        | `#ffffff` | Blanc pur, fond et surfaces                 |
| `--av-paper`        | `#f7f5ef` | Papier chaud, surface secondaire            |
| `--av-paper-warm`   | `#ece4d0` | Papier plus chaud (accents doux)            |
| `--av-ink`          | `#17232d` | Encre, texte fort                           |
| `--av-ink-soft`     | `#394956` | Encre atténuée, texte courant               |
| `--av-muted`        | `#697985` | Texte secondaire, métadonnées               |
| `--av-blue`         | `#104a88` | **BLEU — structure primaire**               |
| `--av-blue-deep`    | `#123b62` | Bleu profond, bordure de bouton primaire    |
| `--av-blue-light`   | `#e8f2f8` | Bleu clair, fonds de survol/actif           |
| `--av-cyan`         | `#00a8c8` | **CYAN — liens, connexions, interactions**  |
| `--av-cyan-soft`    | `#dff5f7` | Cyan doux, halos de focus, fonds fédérés    |
| `--av-gold`         | `#c9a84c` | **DORÉ — accent, souligné**                 |
| `--av-gold-soft`    | `#f5ecd2` | Doré doux, fonds d'accent                   |
| `--av-green`        | `#28765e` | Vert — succès, service en ligne             |
| `--av-green-soft`   | `#e4f2eb` | Vert doux, fonds de succès                  |
| `--av-red`          | `#a73d42` | Rouge — erreur, danger, privé               |
| `--av-orange`       | `#c87832` | Orange — attention, maintenance             |
| `--av-border`       | `#d9e0e4` | Filets, bordures par défaut                 |
| `--av-border-strong`| `#aebbc3` | Bordures marquées (champs, boutons neutres) |

### Rôles sémantiques (à préférer aux couleurs brutes)

| Jeton            | Pointe vers (clair) | Usage                          |
|------------------|---------------------|--------------------------------|
| `--av-bg`        | `--av-white`        | Fond de page                   |
| `--av-surface`   | `--av-white`        | Surface de carte/panneau       |
| `--av-surface-2` | `--av-paper`        | Surface atténuée, survol       |
| `--av-text`      | `--av-ink`          | Texte principal                |
| `--av-text-soft` | `--av-ink-soft`     | Texte courant                  |
| `--av-text-muted`| `--av-muted`        | Texte secondaire               |
| `--av-primary`   | `--av-blue`         | Action/structure primaire      |
| `--av-secondary` | `--av-cyan`         | Action secondaire, liaison     |
| `--av-accent`    | `--av-gold`         | Accent                         |
| `--av-line`      | `--av-border`       | Filets                         |
| `--av-line-strong`| `--av-border-strong`| Filets marqués                |

**Toujours consommer les rôles** (`--av-surface`, `--av-text`…) plutôt que les
teintes brutes : ce sont eux qui basculent en sombre.

### Thème sombre

Trois états, dans cet ordre exact (voir `tokens.css`) :

1. **Clair** par défaut sur `:root` nu.
2. **Sombre automatique** sous `@media (prefers-color-scheme:dark)`, mais
   **seulement si** l'utilisateur n'a pas forcé le clair :
   `:root:not([data-theme="light"])`.
3. **Sombre explicite** via `:root[data-theme="dark"]`, qui gagne dans les deux
   sens.

En sombre, les rôles se réaffectent (fond `#0f1a24` bleu-nuit, jamais noir pur ;
`--av-primary` passe à `#5aa0e0`, etc.). **Règle** : une couleur ne doit jamais
être définie *uniquement* dans un bloc sombre — toujours une valeur claire de
base, puis un remplacement.

---

## 2. Typographie

| Famille        | Variable            | Usage                          |
|----------------|---------------------|--------------------------------|
| Cinzel         | `--av-font-display` | Titres (`.av-display`), logo   |
| Inter          | `--av-font-body`    | Interface & lecture (corps)    |
| JetBrains Mono | `--av-font-mono`    | Données, logs, adresses        |

Auto-hébergées via `@font-face` (`css/typography.css`), `font-display:swap`,
avec piles de repli système (`Georgia`, `system-ui`, `ui-monospace`).

| Classe             | Rôle                                                     |
|--------------------|----------------------------------------------------------|
| `.av-display`      | Titre. `h1.av-display` et `h2.av-display` en `clamp()`.  |
| `.av-eyebrow`      | Sur-titre cyan, majuscules espacées.                     |
| `.av-lede`         | Chapô, borné à `--av-reading-width`.                     |
| `.av-mono`         | Passage en JetBrains Mono.                               |
| `.av-section-title`| Titre de bloc + filet + `<small>` mono à droite.         |

Largeur de lecture bornée à `--av-reading-width` (`68ch`) partout où l'on lit.

---

## 3. Espacement, rayon, ombre

**Espacement** (échelle) — `--av-space-1`=.25rem, `-2`=.5, `-3`=.75, `-4`=1rem,
`-6`=1.5, `-8`=2, `-12`=3, `-16`=4rem.

**Rayon** — `--av-radius-sm`=6px, `-md`=10px, `-lg`=16px, `-xl`=24px,
`-pill`=999px.

**Ombre** — `--av-shadow-xs` (cartes au repos), `--av-shadow-sm` (survol),
`--av-shadow-md` (héros, éléments détachés).

**Gabarit** — `--av-content-width`=1180px, `--av-reading-width`=68ch,
`--av-sidebar-width`=230px.

---

## 4. Composants

### Ossature (`layout.css`)
| Classe          | Quand l'utiliser                                        |
|-----------------|---------------------------------------------------------|
| `.av-theme`     | Sur `<body>` : colonne pleine hauteur.                  |
| `.av-header`    | En-tête collant, verre dépoli.                          |
| `.av-shell`     | Grille barre latérale + contenu.                        |
| `.av-sidebar`   | Colonne de navigation collante.                         |
| `.av-main`      | Colonne de contenu, blocs empilés.                      |
| `.av-block`     | Une section de contenu.                                 |
| `.av-grid`      | Grille `auto-fit` (min 230px).                          |
| `.av-footer`    | Pied de page (+ `.av-footer-cols`, `.av-story-footer`). |

### Navigation (`navigation.css`)
`.av-logo`, `.av-nav` / `.av-nav-item`, `.av-railnav`, `.av-railhead`. L'état
courant est porté par `aria-current="page"` — jamais une classe décorative
seule.

### Boutons (`components.css`)
Base `.av-button` + variantes : `--primary`, `--secondary`, `--ghost`,
`--danger`, `--success`. Les couleurs passent par des variables locales
(`--_bg/_fg/_bd`), ce qui rend les variantes minimales. **Quand** : `--primary`
pour l'action principale unique d'un écran ; `--ghost` pour une action discrète
(annuler, basculer) ; `--danger`/`--success` pour les actes irréversibles.

### Héros, dévoilement, ambiance (`components.css`)
`.av-hero` (+ `.av-hero-in`, `.av-accentbar`, `.av-hero-actions`), `.av-reveal`
(effet de rideau au survol/focus), `.av-network-pattern` (constellation),
`.av-terminal` / `.av-log` (journaux). **Quand** : un héros par page, en tête.

### Cartes & contenus (`cards.css`)
| Classe              | Quand                                                 |
|---------------------|-------------------------------------------------------|
| `.av-card`          | Bloc de contenu générique. Variantes `--feature`, `--info`, `--success`, `--warning`, `--critical`, `--transparent`. |
| `.av-service-card`  | Ligne « icône + libellé + état » d'un service.        |
| `.av-post`          | Publication (BBS/Mastodon) : fiche éditoriale.        |
| `.av-dashboard` / `.av-stat` / `.av-meter` | Vignettes chiffrées, jauge.    |

### Formulaires (`forms.css`)
`.av-field`, `.av-label`, `.av-input`, `.av-textarea`, `.av-select`, `.av-help`,
`.av-error`, `.av-toggle`. Le focus pose bordure cyan **+** halo `box-shadow` :
deux signaux, pas un.

### Tables (`tables.css`)
`.av-table-wrap` (conteneur qui défile seul) + `.av-table`. Variante
`--technical` : première colonne en mono. **Quand** : toute donnée tabulaire ;
toujours enveloppée dans `.av-table-wrap` pour le défilement mobile.

### Messages système (`dialogs.css`)
`.av-alert` + `--info`/`--success`/`--warning`/`--danger`, `.av-empty` (état
vide encourageant), `.av-soap-bubble` (demi-bulle pédagogique : citations,
conseils, morales).

---

## 5. États & provenance (`badges.css`)

**Règle absolue : jamais différenciés par la seule couleur.** Chaque pastille
porte un point/glyphe ET un libellé texte.

- **États** — `.av-status--online`, `--offline`, `--warning`, `--loading`
  (pulse), `--private`, `--public`, `--federated`, `--local`.
- **Provenance/fédération** — `.av-origin--local` (◆), `--federated` (⇄),
  `--mirror` (◎), `--external` (↗).

---

## 6. Accessibilité (`accessibility.css`)

- **Focus visible** : anneau cyan cohérent au clavier (`:focus-visible`). Les
  boutons et champs posent en plus leur propre focus.
- **Mouvement réduit** : sous `prefers-reduced-motion:reduce`, animations et
  transitions sont ramenées à `.01ms`.
- **Lecteurs d'écran** : `.av-sr-only` retire visuellement sans retirer du flux
  (jamais `display:none`, qui masque aussi aux synthèses vocales).
- **Cible tactile** : `.av-tap-target` (opt-in) garantit 44×44 px sur les
  commandes isolées d'une interface tactile — non imposé à tous les boutons,
  pour préserver le rendu validé.
- **Couleur jamais seule** : états, origines et alertes doublent toujours la
  teinte d'une icône et d'un mot.

---

## 7. Adaptatif (`responsive.css`)

Le responsive est d'abord **en ligne** dans les composants : `clamp()` sur les
titres, `grid auto-fit` sur les grilles, `overflow-x` sur les tables. Ne reste
en media query qu'un pli sous **860 px** : la coquille passe à une colonne, la
barre latérale devient un bandeau horizontal, la navigation d'en-tête s'efface
au profit du rail. Ces règles sont écrites **en fin de cascade** — une media
query n'ajoute aucune spécificité et serait sinon écrasée.

---

## 8. Impression (`print.css`)

Sous `@media print` : fond blanc, texte noir, contraste maximal. Le chrome
(en-tête, rail, pied, motif du héros, bascule de thème) disparaît, la coquille
se déplie sur une colonne, les ombres cèdent la place à une bordure franche, les
liens redeviennent noirs et soulignés.
