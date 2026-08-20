<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# AletheiaVox — Design System

AletheiaVox est la peau commune des services souverains SecuBox : un forum
(BBS), une vidéo (PeerTube), un réseau social (Mastodon) et les tableaux de bord
d'administration, réunis sous **une même identité visuelle**. Un socle de jetons
CSS (`--av-*`), un jeu de composants (`.av-*`) et un point d'entrée unique
(`css/aletheiavox.css`) suffisent à habiller n'importe quelle surface. Clair par
défaut sur fond blanc, sombre bleu-nuit sur choix explicite — jamais imposé par
le système.

## Philosophie

**L'information devant, la technologie derrière.** Une publication ressemble à
une fiche éditoriale, pas à une carte de réseau social commercial ; un état de
service se lit à la fois par une couleur ET par un mot ; le réseau reste
perceptible (la constellation du héros) sans jamais devenir envahissant. Le nom
même — *aletheia*, la vérité dévoilée — porte cette exigence de lisibilité :
rien n'est caché, rien ne crie. Trois couleurs suffisent à tout dire : le
**bleu** structure, le **cyan** relie, le **doré** souligne.

**Modulaire et réutilisable, sans build.** Tout est en CSS natif : des custom
properties pour les jetons, des `@import` pour la composition, aucune étape de
compilation. On intègre une application tierce en remappant ses variables vers
les jetons `--av-` (cas idéal, quelques lignes) ou en surchargeant ses classes
connues — **jamais** en touchant à sa logique, son HTML ou son JavaScript. La
maquette validée (`demo/index.html`) est la référence : toute divergence entre
le code et elle est un défaut, pas une réinterprétation.

## Démarrage rapide

Une seule feuille à charger — l'ordre des `@import` internes EST la cascade :

```html
<link rel="stylesheet" href="css/aletheiavox.css">
```

Puis on écrit du balisage avec les classes `.av-*` :

```html
<body class="av-theme">
  <article class="av-card av-card--feature">
    <span class="av-eyebrow">À la une</span>
    <h3>Souveraineté</h3>
    <p class="av-muted">Vos données restent chez vous.</p>
    <button class="av-button av-button--primary">Explorer</button>
  </article>
</body>
```

Basculer en sombre = poser `data-theme="dark"` sur `<html>` (et `"light"` pour
forcer le clair même sous OS sombre) :

```js
document.documentElement.setAttribute('data-theme', 'dark');
```

Avant la première utilisation, copier les trois polices dans `assets/fonts/`
(voir `assets/fonts/README.md`). Sans elles, le rendu retombe proprement sur les
polices système. Le catalogue complet des composants est dans `demo/index.html`.

## Carte du dépôt

```
aletheiavox-theme/
├── README.md              Ce fichier — quoi, pourquoi, comment démarrer
├── DESIGN-SYSTEM.md       Référence : jetons, composants, états, a11y, print
├── INTEGRATION.md         Intégrer une appli existante (BBS = exemple travaillé)
├── css/
│   ├── tokens.css         Le bloc :root — clair + sombre auto + sombre explicite
│   ├── reset.css          Remise à zéro minimale
│   ├── typography.css     @font-face auto-hébergés + classes de texte
│   ├── layout.css         Ossature : header, shell, sidebar, main, footer
│   ├── navigation.css     Logo, nav, rail
│   ├── components.css     Boutons, héros, reveal, terminal, animations
│   ├── cards.css          Cartes, services, publications, vignettes chiffrées
│   ├── forms.css          Champs, libellés, aide/erreur, interrupteur
│   ├── tables.css         Tableaux (+ variante --technical)
│   ├── badges.css         États (av-status) & provenance (av-origin)
│   ├── dialogs.css        Alertes, état vide, demi-bulle
│   ├── utilities.css      av-muted, av-cluster, nuancier, helpers d'espacement
│   ├── accessibility.css  Focus, mouvement réduit, sr-only, cible tactile
│   ├── responsive.css     Paliers d'adaptation
│   ├── print.css          Feuille d'impression
│   └── aletheiavox.css     Point d'entrée : @import de tout, dans l'ordre
├── integrations/
│   ├── generic.css        Le patron d'intégration commenté
│   ├── bbs.css            Intégration de RÉFÉRENCE (secubox-bbs)
│   ├── mastodon.css       Surcharge des classes Mastodon
│   ├── peertube.css       Surcharge des classes PeerTube
│   └── secubox.css        Face membre vs face sysop (même ADN, admin plus dense)
├── assets/
│   ├── fonts/README.md    Où déposer cinzel/inter/jetbrainsmono.woff2
│   └── patterns/network.svg  La constellation du héros, en fichier autonome
└── demo/
    └── index.html         Catalogue vivant — tous les composants sur une page
```

## Licence

Source-Disclosed License — LicenseRef-CMSD-1.0. Voir `LICENCE-CMSD-1.0.md` à la
racine du dépôt.
