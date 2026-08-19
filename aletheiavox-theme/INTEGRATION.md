<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Intégrer AletheiaVox dans une application existante

Ce guide explique comment habiller une application tierce (Mastodon, PeerTube,
un panneau SecuBox…) en AletheiaVox **sans jamais toucher à sa logique**. On
n'ajoute que du CSS chargé par-dessus.

## Principe cardinal : on ne patche jamais l'appli

- **Pas** de modification du HTML rendu, des gabarits, du JavaScript ou du code
  serveur de l'application.
- **Pas** de renommage de ses classes.
- On charge d'abord `css/aletheiavox.css` (jetons + composants), **puis** une
  feuille d'intégration qui repeint par-dessus.
- On passe par le mécanisme prévu par l'appli pour du CSS personnalisé (champ
  « CSS custom » d'admin, `public/custom.css`, thème, dropin nginx servant une
  feuille en plus…).

Si l'habillage exige de changer le DOM ou le JS, c'est que le design system doit
gagner un composant — on l'ajoute au système, pas un rustine dans l'appli.

## Étape 1 — Inspecter le DOM

Ouvrir l'application dans le navigateur, inspecter les éléments réels et
répondre à **une** question : *l'application expose-t-elle ses propres variables
CSS (custom properties) ?*

- Regarder `:root` / `body` dans l'inspecteur : y a-t-il des `--quelquechose` ?
- Repérer les classes structurantes (conteneur, carte, bouton, en-tête).

De la réponse découlent deux chemins.

## Étape 2A — L'appli EXPOSE des variables → on les REMAPPE

C'est le cas idéal. On redéfinit les variables natives de l'appli **en termes de
jetons `--av-`**. Quelques lignes repeignent tout.

```css
:root{
  --app-bg:      var(--av-bg);
  --app-surface: var(--av-surface);
  --app-text:    var(--av-text);
  --app-primary: var(--av-primary);
  --app-accent:  var(--av-accent);
}
```

## Étape 2B — L'appli n'a PAS de variables → on SURCHARGE ses classes

On cible les sélecteurs connus repérés à l'étape 1 et on les branche sur les
jetons `--av-`. Voir `integrations/mastodon.css` et `integrations/peertube.css`
pour des exemples complets. Toujours vérifier le DOM **réel** : les noms de
classes évoluent d'une version à l'autre.

```css
.status{background:var(--av-surface);border-bottom:1px solid var(--av-line)}
.status__content{color:var(--av-text-soft);max-width:var(--av-reading-width)}
.button{background:var(--av-primary);color:#fff;border-radius:var(--av-radius-md)}
```

## Exemple travaillé — secubox-bbs (intégration de RÉFÉRENCE)

Le BBS est le cas 2A abouti. Il a son propre vocabulaire, hérité de sa maquette :
`--ink`, `--paper`, `--sky`, `--violet`, `--pink`… Les **teintes** étaient déjà
celles d'AletheiaVox, mais chaque hex était recopié à la main dans le BBS. On les
rebranche sur les jetons canoniques — `css/tokens.css` devient la seule source de
vérité des couleurs.

Correspondance déployée (voir `integrations/bbs.css`,
et `packages/secubox-bbs/internal/web/static/bbs.css` côté application) :

| Variable BBS | Rôle dans le BBS               | → Jeton AletheiaVox            |
|--------------|--------------------------------|--------------------------------|
| `--ink`      | Encre / texte fort             | `--av-ink`                     |
| `--paper`    | Fond de page (BLANC)           | `--av-white`                   |
| `--panel`    | Surface de carte               | `--av-surface`                 |
| `--line`     | Filets, bordures               | `--av-border`                  |
| `--soft`     | Fond atténué, survol           | `--av-surface-2`               |
| `--dim`      | Texte secondaire               | `--av-muted`                   |
| `--text`     | Texte courant                  | `--av-ink`                     |
| `--sky`      | **BLEU — structure primaire**  | `--av-blue` (soft → `--av-blue-light`) |
| `--violet`   | **CYAN — liens/interactions**  | `--av-cyan` (soft → `--av-cyan-soft`)  |
| `--pink`     | **DORÉ — accent, souligné**    | `--av-gold` (soft → `--av-gold-soft`)  |
| `--mint`     | Vert — succès / actif          | `--av-green` (soft → `--av-green-soft`)|
| `--amber`    | Orange — attention             | `--av-orange`                  |
| `--coral`    | Rouge — erreur / danger        | `--av-red`                     |

Le remap tient en un bloc `:root{…}` (et un bloc `:root[data-theme="dark"]{…}`
qui rebranche le sombre du BBS sur les jetons sombres). **Aucune** des centaines
de règles du BBS n'est modifiée : elles lisent toujours `var(--sky)`, mais
`--sky` pointe désormais sur `--av-blue`.

Détail important : le BBS impose un **fond blanc même sous OS sombre** — le
sombre y est un choix explicite (`[data-theme="dark"]`), jamais imposé par
`prefers-color-scheme`. `integrations/bbs.css` respecte ce contrat en ne
rebranchant le sombre que sous l'attribut explicite.

Les polices, elles, sont déjà partagées : les `@font-face` auto-hébergés de
`css/typography.css` sont repris tels quels du BBS (CSP `default-src 'self'` →
pas de police externe). Rien à redéclarer.

## Cas particulier — surfaces SecuBox (membre vs sysop)

`integrations/secubox.css` distingue deux publics au **même ADN** : la face
membre (on lit — réglage par défaut, aéré) et la face sysop (on pilote — même
peau, plus **dense**). Le fichier ne redéfinit aucune couleur ; il resserre
seulement espacements et tailles sous une classe de contexte `.av-admin`. À ne
pas confondre avec le terminal cyan historique des panneaux d'administration
(`WEBUI-PANEL-GUIDELINES.md`), qui reste son propre langage.

## Ordre de chargement (récapitulatif)

```html
<link rel="stylesheet" href="css/aletheiavox.css">       <!-- 1. jetons + composants -->
<link rel="stylesheet" href="integrations/bbs.css">      <!-- 2. remap/surcharge de l'appli -->
```

Toujours dans cet ordre : les jetons doivent exister avant que l'intégration ne
les référence.

## Liste de contrôle avant déploiement

- [ ] `css/aletheiavox.css` chargé **avant** la feuille d'intégration.
- [ ] Les trois `.woff2` sont présents (voir `assets/fonts/README.md`).
- [ ] Le DOM réel a été inspecté ; les sélecteurs surchargés existent bien.
- [ ] Aucune ligne de code de l'application n'a été modifiée.
- [ ] Testé en clair, en sombre auto (OS), et en sombre explicite.
- [ ] États et alertes restent lisibles sans la couleur (icône + texte).
