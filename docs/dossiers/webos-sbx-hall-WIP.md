<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Fichier VIVANT de reprise pour #1175. À mettre à jour en fin de session.
  Le « quoi/pourquoi » est dans webos-sbx-hall-cardlets.md ; ici seulement
  l'état courant, l'historique daté et le prochain pas.
-->

# WebOS SBX / Hall — WIP, historique & TODO (#1175)

**Dernière mise à jour** : 2026-08-24 (fin de session)
**Branche** : `feature/1175-webos-sbx-hall-cardlets-bureau-numerique`
**Worktree** : `secubox-deb-worktrees/1175-webos-sbx-hall-cardlets-bureau-numerique`
**Dépôt principal** : `secubox-deb/secubox-deb` (master) · remotes `origin` (GitHub
CyberMind-FR) + `gitea` (gitea.gk2.secubox.in)
**Paquet** : `secubox-webos` — version **1.0.25** (1.0.24 mergée dans master)

## 1. État courant
- Branche **1 commit devant `origin/master`** : `9632e62de` référence de rendu SBXOS.
  **Non poussé, non mergé** → premier geste de la reprise.
- Tout le reste de #1175 (jusqu'à 1.0.24) est **déjà dans `master`**.
- Le Hall vit sur `hall.gk2.net` / `hall.gk2.secubox.in`, vhost nginx port 9080,
  API registre via `unix:/run/secubox/webos.sock`, CSP sans origine tierce.

## 2. Historique — session 2026-08-24
Journée passée à rendre le **mégamenu utilisable sur smartphone**, quatre causes
distinctes empilées (chacune masquait la suivante) :

| Ver. | Cause trouvée | Correctif |
|---|---|---|
| 1.0.20 | flyout rogné par l'`overflow` du mégamenu ; 1ᵉʳ tap iOS absorbé par `:hover` | bulles en `position:fixed` calculées en JS ; règles `:hover` sous `@media(hover:hover)` ; voile de fond transparent |
| 1.0.21 | déclencheurs non-`<button>` → iOS n'émettait pas de `click` au 1ᵉʳ tap | vrais `<button type=button>` ; menubar macOS à 2 menus (Services / Système) |
| 1.0.22 | **commentaire de licence AVANT `<!DOCTYPE html>`** → iOS Safari en **Quirks Mode**, `position:fixed`/`sticky` cassés, mégamenu injoignable | doctype remis en **tout premier octet** |
| 1.0.23 | panneaux portant la classe `rail`, or `@media(max-width:820px){.rail{display:none}}` → panneau `display:none` sur **tout** téléphone | retrait de la classe `rail` |
| 1.0.24 | seuils en **largeur** : un téléphone de 700px tombait entre deux règles | détection par **capacité de survol** (`@media(hover:none)` + `matchMedia`) ; sous-menus au tap du chevron ; dropdown borné ≤340px |

**Leçons à ne pas repayer** : (a) doctype en premier octet, toujours ; (b) sur mobile
raisonner en *capacité de survol*, jamais en largeur ; (c) se méfier des classes
héritées d'une ancienne mise en page (`rail`).

**Fin de session** : 1.0.25 — référence de rendu SBXOS (voir §3 du todo).

## 3. TODO — prochaine session, dans l'ordre
1. **Pousser / merger 1.0.25** (`9632e62de`) vers `origin/master` + `gitea`, puis
   `git merge --ff-only origin/master` dans le worktree. *Rien d'autre avant ça.*
2. **Vérifier la réf de rendu sur vrai matériel** : `hall.gk2.net/render-ref.html`
   côte à côte avec `hall.gk2.net/` sur desktop **et iPhone** (le terrain de #1175).
3. **Arbitrer les 4 écarts** listés en §6 de `webos-hall-render-ref.md` — rayon 8px
   vs 13–16px, chrome fenêtre vs masthead, ombres sans `:hover` qui soulève, grille
   2 colonnes fixes vs `auto-fill`. Décision produit, puis alignement d'`index.html`.
4. **Reprendre le backlog « WebOS realtime »** (dossier principal §24), non entamé :
   - injection de la mégabar sur les services **non embarqués** (P6, `sub_filter`) ;
   - **widgets flottants persistants** (pop-up Radio épinglée qui survit à la
     navigation d'un vhost à l'autre) ;
   - trois formes par service : vhost plein / menu embarqué `/menu/<id>` /
     cardlet `/cardlets/<id>` en full·mini·micro ;
   - multi-nœuds dans le registre normalisé (« au prochain ») ;
   - avatar multi-utilisateur famille (cf. `secubox-avatar.md`), sous contrôle sysop.
5. **Réconcilier les tickets widgets** #1170 / #1171 / #1172 dans le modèle cardlet
   commun (tailles `small|medium|wide`, contrat cardlet, adaptateur par module)
   plutôt qu'isolément.

## 4. Points ouverts / non tranchés
- Le chrome « fenêtre macOS » de l'affiche remplace-t-il le masthead AletheiaVox du
  Hall, ou cohabitent-ils selon la vue ? **Non tranché** — bloque le point 3.
- Aucune photo réelle disponible pour la cardlet Photos : la réf utilise des dégradés
  CSS. Décider de la source (PhotoPrism ?) avant d'implémenter.
- L'affiche source n'est **pas** versionnée dans le dépôt (fournie en conversation) ;
  `render-ref.html` en est aujourd'hui la seule trace fidèle.

## 5. Autres worktrees ouverts (hors #1175, pour mémoire)
`1027-depot-le-waf-bloque-les-envois-anonymes` · `1049-mosaique-de-vignettes-partagee-pour-les`
· `secubox-deb-license-wt` (`feature/license-phase-b-full`).
