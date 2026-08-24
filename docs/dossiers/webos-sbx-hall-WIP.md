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

**Dernière mise à jour** : 2026-08-25 (fin de session nuit)
**Branche de travail** : `master` — tout est fusionné et poussé sur `origin`
**Dépôt principal** : `secubox-deb/secubox-deb` · remotes `origin` (GitHub
CyberMind-FR) + `gitea` (gitea.gk2.secubox.in)
**Nœud de test** : `gk2` = `root@192.168.1.200`

## 1. État courant
- `master` = `2ba5d0cd7`, poussé sur `origin`. **`gitea` n'a PAS reçu ce push**
  (dépôt injoignable depuis le poste) → à repousser.
- **#1187 et #1188 sont closes.** **#1175 reste ouverte** : c'est le brief
  chapeau, dont les phases P4→P8 et le backlog §24 ne sont pas entamés.
- Versions livrées : `secubox-webos` 1.0.33 · `secubox-hub` 1.9.10 ·
  `secubox-bbs` 0.30.12 · `secubox-repo` 1.1.2.
- Paquets intégrés au dépôt apt vivant (`/data/apt`, reprepro) en
  **`bookworm-testing`**, signés. Pas en `stable` : à promouvoir si validé.

> ⚠ La box tourne avec des fichiers poussés **à la main** pendant la session
> (rsync/scp) avant que la règle « déploiement uniquement par paquet » ne soit
> posée. dpkg ne connaît pas ce code. **Premier geste de la reprise** :
> réinstaller webos/hub/bbs/repo depuis le dépôt apt pour remettre dpkg
> d'accord avec le disque.

## 2. Historique
### Session 2026-08-24 (jour) — mégamenu mobile
Quatre causes empilées, chacune masquant la suivante :

| Ver. | Cause | Correctif |
|---|---|---|
| 1.0.20 | flyout rogné par l'`overflow` ; 1ᵉʳ tap iOS absorbé par `:hover` | bulles `position:fixed` ; `:hover` sous `@media(hover:hover)` |
| 1.0.21 | déclencheurs non-`<button>` → pas de `click` iOS au 1ᵉʳ tap | vrais `<button type=button>` |
| 1.0.22 | **licence avant `<!DOCTYPE html>`** → iOS Safari en **Quirks Mode** | doctype en tout premier octet |
| 1.0.23 | classe `rail` sur les panneaux, masquée ≤820px | retrait de la classe |
| 1.0.24 | seuils en **largeur** (un téléphone 700px tombait entre deux règles) | détection par **capacité de survol** |

### Session 2026-08-24/25 (nuit) — #1187, #1188, outillage
- **1.0.25** — référence de rendu SBXOS (`/render-ref.html`) + son dossier.
- **1.0.26** — barre système sans sous-menus, panneau contextuel, switch 3 modes.
- **1.0.27** — menus unifiés (emoji + ⚙️ + ⧉), Système en mosaïque.
- **1.0.28** — nav contextuelle en menu pop ; correctif de débordement mobile.
- **1.0.29** — le **titre du service devient son menu** ; Profil/Alertes retirés.
- **1.0.30** — chaque menu s'ouvre sous son bouton (recherche du déclencheur
  rendue globale ; alignement par la droite dans la moitié droite).
- **1.0.31** — le bouton du mode courant s'efface du switch.
- **1.0.32 → 1.0.33** — section « Accès » du BBS remontée puis **retirée**
  (n'apportait rien au menu). Les deux versions ont tourné sur la box.
- **hub 1.9.9 → 1.9.10** — coquille du panneau admin entièrement masquée en
  embarqué (méthode BBS : détection du **cadrage**), règle en
  `.claude/WEBUI-PANEL-GUIDELINES.md §9`.
- **bbs 0.30.11 → 0.30.12** — idem, ajout puis retrait de la section « Accès ».
- **repo 1.1.2** — `repoctl` signe avec l'email du **nœud**.

**Leçons à ne pas repayer** : doctype en premier octet · sur mobile raisonner en
*capacité de survol*, jamais en largeur · se méfier des classes héritées ·
`<a>` imbriqué dans `<a>` est invalide et casse la ligne · une règle CSS placée
avant sa définition de base est écrasée à spécificité égale · vérifier les liens
de release contre les assets réellement publiés.

## 3. TODO — prochaine session, dans l'ordre
1. **Remettre dpkg d'accord avec le disque** (cf. §1) puis **repousser vers
   `gitea`** quand il est joignable.
2. **Médias publics du BBS — NON RÉSOLU, demandé par l'utilisateur.** Symptôme
   rapporté : « sans authent les vignettes et médias sont en partie KO ». Ce qui
   a été établi : `/media-vignette` répond **403 aux anonymes par conception**
   (`// RESERVE AUX MEMBRES`), mais **aucune page publique testée ne l'utilise**,
   et toutes les vignettes `/media-cover/N` répondent 200 en anonyme sauf
   `/media-cover/1` (404). **Panne non reproduite — il manque l'URL exacte.**
3. **Dépôt `apt.secubox.in` : le pool ne contient aucun `.deb`.** Les
   répertoires du pool existent et les index les référencent, mais les 175
   fichiers sont absents → un client apt aurait un 404 sur chaque téléchargement.
   À repeupler, ou à décider d'abandonner au profit de `/data/apt`.
4. **`repoctl` vs reprepro : deux chemins pour un dépôt.** Clarifier lequel fait
   foi (`/data/apt` sert réellement) et retirer l'autre.
5. **Arbitrer les écarts de la réf de rendu** (§6 de `webos-hall-render-ref.md`) :
   rayon 8px vs 13-16px, chrome fenêtre vs masthead, ombres, densité de grille.
6. **Backlog « WebOS realtime »** (dossier principal §24), non entamé :
   injection de la mégabar sur les services non embarqués (P6), widgets
   flottants persistants, trois formes par service, multi-nœuds, avatar famille.
7. **Réconcilier #1170 / #1171 / #1172** dans le modèle cardlet commun.
8. Pas de capture d'écran du dashboard dans le dépôt (demandée par #1188) ;
   `Home-ZH` du wiki non traduite.

## 4. Points ouverts / non tranchés
- Le chrome « fenêtre macOS » de l'affiche remplace-t-il le masthead
  AletheiaVox, ou cohabitent-ils selon la vue ? **Non tranché** — bloque le §3.5.
- Source des photos pour la cardlet Photos (PhotoPrism ?).
- `secubox-bbs` est **arm64 uniquement** (`Architecture: arm64` + `GOARCH`
  figé). Faut-il le passer en `any` pour publier un amd64 ?
- L'affiche SBXOS n'est pas versionnée : `render-ref.html` en est la seule trace.
- Porter le webos en Go ? **Décision : pas maintenant** — 421 lignes, 4 routes,
  et les mesures contredisent l'argument mémoire (webos Python 39,5 Mo contre
  bbs Go 196,5 Mo). Le déclencheur sera le Session Bridge et les adaptateurs
  cardlets en éventail, pas l'agrégateur actuel.

## 5. Autres worktrees ouverts
`1027-depot-le-waf-bloque-les-envois-anonymes` ·
`1049-mosaique-de-vignettes-partagee-pour-les` ·
`secubox-deb-license-wt` (`feature/license-phase-b-full`).
Les worktrees 1175 / 1187 / 1188 sont fusionnés : ils peuvent être retirés.
