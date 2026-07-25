# Task 7 Report — secubox-proxypac panneau réécrit

**Status:** Done.

(Note: this file previously held a stale report for a different plan's
Task 7 — "MetaBlogizer Publish Wizard UI" — overwritten here since it did
not belong to this plan.)

Commit : 240033e1
Tests : `cd packages/secubox-proxypac && python3 -m pytest tests/ -q` → 45 passed
Préoccupations : aucune bloquante — voir détails ci-dessous.

## Fait

- `packages/secubox-proxypac/tests/test_panel.py` créé (Step 1 du brief),
  vérifié FAIL avant réécriture (Step 2), puis PASS après (Step 4).
- `packages/secubox-proxypac/www/proxypac/index.html` réécrit intégralement
  en hybrid-dark (look inspiré de `secubox-picobrew`, non copié verbatim) :
  - `<nav class="sidebar" id="sidebar"></nav>` + `/shared/sidebar.js`.
  - Cartes statut (`.stat-card`) : rôle/tier, échelon WPAD, endpoint SOCKS,
    transparent ON/OFF, IP LAN — alimentées par `GET /status`.
  - Toggle transparent (switch CSS) câblé sur `POST /transparent {on}`.
  - Bloc runbook client : URL PAC (`pac_url` ou fallback `http://<lan_ip>/proxy.pac`),
    URL WPAD, état WPAD (`GET /wpad/state`), et note Firefox concrète :
    `network.proxy.socks_remote_dns=true`, `network.dns.blockDotOnion=false`,
    `network.trr.mode=0` (DoH off).
  - Bouton "Appliquer WPAD" → `POST /wpad/apply`.
  - Règles actives (`GET /rules`) + formulaire override (`POST /override`,
    `DELETE /override/{host}`) : comportement conservé depuis l'ancien panneau.
  - Bloc candidats (`GET /candidates`), best-effort, liste vide tolérée.
  - `esc()` conservée pour échapper tout host injecté dans le DOM.
  - Toasts sur chaque action ; chaque bloc a un fallback "indisponible (…)"
    en cas d'erreur réseau/API — le panneau ne plante jamais un bloc voisin.
  - Jeton : `localStorage.getItem('sbx_token')` lu une fois, propagé via
    `authHeaders()`/`J()` sur **toutes** les requêtes fetch avec
    `Authorization: Bearer …` + `credentials:'same-origin'`.

## Détail technique notable

Les endpoints sont appelés avec des chemins **littéraux complets**
(`/api/v1/proxypac/status`, `/api/v1/proxypac/rules`, etc.) plutôt que par
concaténation `API + '/status'`, car le test vérifie la présence de la
sous-chaîne exacte `/api/v1/proxypac/status` dans le fichier source — une
concaténation JS runtime ne produit pas cette sous-chaîne littérale dans le
HTML. `J()` conserve un fallback `API + path` pour compat si un appel futur
utilise un chemin relatif.

## Validation

- `python3 -m pytest tests/test_panel.py -q` → FAIL avant réécriture (navbar
  manquante), confirmé.
- `python3 -m pytest tests/ -q` (suite complète du paquet, 45 tests dont
  `test_panel.py` et `test_webui_panel.py` pré-existant) → **45 passed**.
- `menu.d/580-proxypac.json` non modifié (déjà conforme : `path == "/proxypac/"`,
  `id == "proxypac"`).

## Préoccupations

- Aucune bloquante.
- Le bloc candidats est en lecture seule (pas de bouton accept/reject dans
  l'UI bien que l'API expose `/candidate/{host}/accept|reject`) — conforme
  au brief qui demandait un bloc "best-effort, liste vide OK", sans exiger
  d'actions dessus.
- Pas de vérification live (board) effectuée ; validation limitée aux tests
  unitaires du paquet, conformément au périmètre de la tâche 7.

## Fix Important — XSS onclick

**Vulnérabilité (confirmée)** : `loadRules()` construisait un handler inline
`onclick="delOverride('${esc(r.host)}')"`. `esc()` échappe les entités HTML,
mais le navigateur décode les entités d'un attribut AVANT de traiter le
contenu de `onclick` comme du JS. Un host tel que `x');alert(document.cookie);//`
(sans espace → passe la seule validation serveur `Override._no_whitespace`)
s'évade de la chaîne JS et exécute du code arbitraire dans la session de tout
viewer cliquant le bouton — vol possible de `sbx_token`. XSS stockée via un
chemin d'entrée légitime (`POST /override`).

**Correctif** : suppression du handler inline interpolé, remplacé par
délégation d'événements — le bouton porte `data-action="del-override"` et
`data-host="${esc(r.host)}"` (toujours échappé HTML pour le contenu/attribut,
mais jamais réinterprété comme JS) ; un unique listener délégué sur `#rules`
lit `btn.dataset.host` et appelle `delOverride(...)` avec la valeur comme
STRING JS pure. Revue du reste du fichier : les autres `onclick`/`onchange`
(`applyWpad()`, `loadAll()`, `addOverride()`, `toggleTransparent(this.checked)`)
sont à valeur fixe, hors liste rendue dynamiquement — laissés inchangés,
comportement fonctionnel identique (add/del override, apply wpad, toggle
transparent, refresh).

**TDD** : ajout de `test_no_inline_handler_interpolates_dynamic_data` dans
`tests/test_panel.py` — échoue sur le code vulnérable
(`AssertionError: handler inline interpole une donnée: onclick="delOverride('${esc(r.host)}')"`),
passe après le correctif.

**Validation** :
```
cd packages/secubox-proxypac && python3 -m pytest tests/test_panel.py tests/test_webui_panel.py -q
.....                                                                    [100%]
5 passed in 0.07s
```

**Préoccupations** : aucune bloquante. Le reste du fichier ne contient aucun
autre handler inline interpolant une donnée dynamique (vérifié par le test,
qui scanne tout `on(click|change|input|submit)="..."`/`'...'` du fichier).
