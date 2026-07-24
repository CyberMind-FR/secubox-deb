# Task 7 Report — Panel /rlevel (table peers + badges + self-service + navbar)

**Status:** Done.

(Note: this file previously held a stale Task-7 report for an unrelated plan —
overwritten here as instructed.)

## Fichiers

- `packages/secubox-toolbox/www/rlevel/index.html` (nouveau) — panneau webui.
- `packages/secubox-toolbox/menu.d/27-rlevel.json` (nouveau) — entrée navbar.
- `packages/secubox-toolbox/tests/test_rlevel_panel.py` (nouveau) — 13 tests.

## Contrat API respecté (task 6, déjà déployée)

Vérifié directement contre `secubox_toolbox/api.py` (routes `/rlevel/*`, lignes
~4133-4260) et `tests/test_rlevel_api.py` avant d'écrire le panneau :
- `GET /rlevel/peers` (admin) → `{peers:[{pubkey,label,chosen,forced,floor,
  effective,live}], defaults}`.
- `POST /rlevel/peer` (admin) → body `{pubkey, floor?, forced?}` — pubkey
  **dans le body**, jamais dans l'URL (base64 avec `/`).
- `GET /rlevel/me` / `POST /rlevel/me {chosen}` (peer, identité = IP tunnel).
- Préfixe de montage confirmé sur `www/toolbox/index.html` (`const API =
  '/api/v1/toolbox'`) — repris tel quel : `API + '/rlevel/peers'` etc.

## TDD

1. Test écrit en premier (13 cas) → **RED** : 13 FAILED (fichiers absents).
2. Implémentation : `menu.d/27-rlevel.json` + `www/rlevel/index.html`.
3. Un aller-retour : les 4 badges de mode avaient une règle CSS sans `;` final
   avant `}`, ce qui faisait déborder le regex de test `[^;]+;` du garde
   badges dans les règles suivantes → corrigé (`;` ajouté).
4. **GREEN** : `python3 -m pytest tests/test_rlevel_panel.py -q` → `13 passed`.
5. Suite complète du paquet : `335 passed`, 3 échecs **pré-existants sans
   rapport** (`test_bypass_sources.py`, `test_media_stats.py` — `ModuleNotFoundError:
   secubox_core`, confirmé identique hors branche via `git stash`).

## Ce qui a été construit

- **Navbar** : `<nav class="sidebar" id="sidebar">` + `<script src="/shared/
  sidebar.js">`, `hybrid-skin.css` + `hybrid-dark.css`, `body class=
  "hybrid-dark"`, palette cyan verbatim (§2 WEBUI-PANEL-GUIDELINES), Courier
  Prime — modèle `/certs/` + `/wireguard/`.
- **Auth** : chaque appel passe par un wrapper `api(path, opts)` unique qui
  pose systématiquement `Authorization: 'Bearer ' + (localStorage.getItem(
  'sbx_token') || '')` **et** `credentials: 'same-origin'` — GET comme POST,
  aucun fetch direct en dehors de ce wrapper.
- **Badges 4 modes** (`.badge-off/passive/active/reel`), 4 couleurs
  distinctes : gris (`--grey`), cyan, orange, violet.
- **Table admin** (`GET /rlevel/peers`) : label + pubkey tronquée (titre =
  pubkey complète, `esc()`'d), badge chosen, `<select>` floor, `<select>`
  forced (`(none)` = déverrouillé), badge effective, pastille live, boutons
  **Apply** (`POST /rlevel/peer` avec `{pubkey, floor, forced?}`) et
  **Unlock** (`{pubkey, forced: null}`).
- **Self-service** (`GET/POST /rlevel/me`) : carte dédiée, badges
  effective/chosen/floor ; si `forced` actif → message verrouillé (pas de
  contrôle) ; sinon `<select>` + bouton Apply lié par `addEventListener`
  (pas d'inline).
- **Délégation d'événements (garde XSS)** : un seul listener sur `#peersBody`
  lisant `e.target.closest('[data-action]')` puis `.dataset.pubkey` /
  `.dataset.action` — **aucun** `onclick="...${pubkey}..."`. Les deux
  `onclick` statiques restants (`loadPeers()` sur le bouton Refresh) ne
  contiennent aucune interpolation de donnée API.
- **`esc()`** appliqué à `label`, `pubkey` (texte ET attribut `title`/
  `data-pubkey`) et `forced` avant toute injection `innerHTML`.
- **Dégradation propre** : chaque chemin réseau est dans un `try/catch` ;
  403 (source non-admin / non-peer) affiche un message dédié au lieu de
  planter ; erreurs réseau → texte `⚠️` dans le tableau ou toast rouge
  persistant (clic pour fermer).

## Garde XSS — vérification explicite

Le test `test_no_inline_handler_interpolates_api_data` applique le regex du
brief (`on\w+\s*=\s*["'][^"']*["']` puis filtre `${` dans le match) sur le
HTML final : **aucun** handler inline n'interpole de donnée. Toutes les
actions par ligne utilisent `data-*` + délégation.

## Vérification

```
cd packages/secubox-toolbox && python3 -m pytest tests/test_rlevel_panel.py -q
# 13 passed
node --check <script extrait>   # OK, pas d'erreur de syntaxe
python3 -c "import json; json.load(open('menu.d/27-rlevel.json'))"  # OK
```

## Préoccupations

- Le montage réel de `/rlevel/` (nginx alias ou `app.mount` côté FastAPI,
  ainsi que l'entrée `debian/rules`/`.install`) est **hors périmètre de cette
  tâche** — confirmé dans le plan (`docs/superpowers/plans/
  2026-07-24-rlevel-per-peer.md`, Task 8 : "Packaging + cross-build") : c'est
  la tâche 8 qui installera le panneau + menu.d dans le `.deb`. Le panneau et
  son test sont livrés ; le wiring paquet reste à faire par task 8.
- Deux fichiers de suivi non liés à cette tâche
  (`.superpowers/sdd/task-2-report.md`, `task-5-report.md`) apparaissent
  modifiés dans l'arbre de travail au moment de cette tâche (pas mon fait —
  aucune modification de ma part) ; laissés intacts, non ajoutés au commit.
