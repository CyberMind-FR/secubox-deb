<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# R-level MITM par peer wg-toolbox — Design

**Date :** 2026-07-24
**Statut :** validé (design), prêt pour le plan d'implémentation
**Module :** `secubox-toolbox-ng` (sbxmitm) + surface webui/API toolbox

---

## Objectif

Régler **dynamiquement le niveau d'inspection MITM (R-level) par peer wg-toolbox**,
avec statut temps réel dans le webui admin, choix côté peer (borné) et reprise de
contrôle admin (mode forcé). Aujourd'hui l'inspection sbxmitm est globale / par-hôte
(splice-learned), pas par-client.

## Décisions actées

1. **Cible = peer wg-toolbox**, identifié par sa **clé publique wg** (résolue en IP
   `10.99.x` au moment du flux via `wg-peers.json`).
2. **4 modes, échelle croissante d'intrusion** (chaque cran englobe le précédent) :
   | Mode | Comportement | Appliqué où |
   |---|---|---|
   | **off** | bypass, non inspecté (direct) | **nft** — l'IP peer est exclue du DNAT→mitm |
   | **passive** | splice/passthrough : log SNI/JA4/méta, **pas** de déchiffrement | sbxmitm |
   | **active** | MITM déchiffré : contenu, DPI, injection bannière | sbxmitm |
   | **reel** | active **+ enforcement temps réel** : block + ban + rewrite | sbxmitm |
3. **Autorité = self-service borné + override admin.**
   - Chaque peer choisit son `chosen` dans `[floor, reel]` (il peut **monter**
     l'inspection, pas descendre sous le `floor` imposé par l'admin).
   - L'admin peut **forcer** un mode (`forced`) qui verrouille et ignore le choix.
   - **Mode effectif** (fonction pure) : `forced ?? clamp(chosen, floor, "reel")`.
4. **Défauts & fail-safe = passive.** Nouveau peer inconnu → `passive` ; `floor` par
   défaut → `passive` ; table de politique illisible/corrompue → `passive` pour tous
   (jamais off silencieux, jamais déchiffrement d'office). Audit minimal garanti,
   zéro casse de connectivité, escalade active/reel toujours explicite.
5. **Self-service authentifié par l'identité tunnel** (a1) : le peer règle son mode
   via une page portail **atteignable seulement via le tunnel** ; il est identifié par
   son IP `10.99.x` → pubkey. Pas de login séparé (le tunnel EST l'authentification).
6. **Enforcement `reel` complet d'emblée** (b2) : block + ban + rewrite temps réel
   (réutilise les mécanismes sbxmitm/WAF/DPI existants), gated par peer.

## Contexte (mémoire + à vérifier en implémentation)

- R3 = Go **sbxmitm**, workers `secubox-toolbox-ng-worker@1..4`, binaire
  `/usr/sbin/sbxmitm`, cross-compilé arm64 offline (`GOARCH=arm64 -mod=vendor`).
- Le trafic des peers wg-toolbox est **DNAT'd** (test skuid-0) vers les workers mitm.
  → Le mode **off** = retirer l'IP du peer de ce DNAT (nft), vrai bypass.
- **splice = passthrough** existant (TLS non déchiffré) → base du mode **passive**.
- Le déchiffrement (uTLS `uchromeTransport`, `mitmPipeline`) → base **active**.
- Enforcement existant (block whole-site, ban, autolearn) → base **reel**.
- **À VÉRIFIER en source avant le plan** : point exact où un worker connaît l'IP
  source du flux, comment mapper IP→pubkey côté worker, où brancher la décision
  splice-vs-decrypt-vs-enforce par flux, format de `wg-peers.json`, mécanisme de
  hot-reload des workers (signal/inotify), et comment l'existant splice-learned
  (par-hôte) cohabite avec la politique par-peer (précédence).

## Composants

| Fichier / élément | Rôle |
|---|---|
| `/etc/secubox/toolbox/peer-rlevel.json` (owner `secubox:secubox`) | Politique par pubkey : `{chosen, forced, floor, name}` + défauts globaux |
| `rlevel` (Go, dans sbxmitm) | fonction pure `effective(chosen, forced, floor)` + chargement fail-safe passive + hot-reload |
| résolution par flux (worker) | IP `10.99.x` → pubkey → mode effectif → route splice/decrypt/enforce ; off jamais atteint (nft) |
| dropin nft `secubox-toolbox-rlevel-off.nft` | exclut du DNAT→mitm les IP des peers en mode effectif `off` (régénéré par le ctl) |
| `sbxmitm-policyctl` (ctl root scopé) | écrit `peer-rlevel.json` + régénère le dropin nft off + signale les workers ; sudoers exact |
| API toolbox `/rlevel/*` | admin : liste peers+statut, set floor, force/unforce ; **portail peer** : get/set son propre `chosen` (auth par IP tunnel) |
| panneau webui `/rlevel` (ou onglet toolbox) | table peers : mode effectif (badge), source, floor, statut live wg, compteurs flux ; contrôles admin + self-service peer |

## Modèle de données

```json
{
  "defaults": { "mode": "passive", "floor": "passive" },
  "peers": {
    "<pubkey-b64>": { "name": "gk-laptop", "chosen": "active", "forced": null, "floor": "passive" }
  }
}
```
`chosen`/`floor`/`forced` ∈ `{off, passive, active, reel}` (forced peut être `null`).
Ordre : `off(0) < passive(1) < active(2) < reel(3)`.
**Effectif** : `forced ?? min(max(chosen, floor), reel)`.
Un peer absent de `peers` → `{chosen: defaults.mode, floor: defaults.floor, forced: null}`.

## Résolution par flux (sbxmitm worker)

1. Worker reçoit un flux DNAT'd depuis une IP `10.99.x`.
2. Map IP → pubkey (via `wg-peers.json`, mis en cache, rafraîchi au hot-reload).
3. `mode = effective(peer.chosen, peer.forced, peer.floor)` (défauts si absent).
4. Aiguillage :
   - **passive** → splice (pas de déchiffrement, log méta). *(off n'arrive jamais ici : nft.)*
   - **active** → MITM déchiffré (uchrome), DPI, bannière.
   - **reel** → active + hooks enforcement (block/ban/rewrite).
5. **Précédence avec splice-learned par-hôte** : un hôte en splice-learned (cert-pinning,
   banques) reste splice **même en active/reel** (on ne casse pas un hôte connu-pinné) —
   le R-level élève le *plancher d'inspection du peer*, le splice-learned reste un
   *garde-fou par-hôte* qui prime pour éviter les 502. *(à confirmer : c'est la
   sémantique sûre ; l'alternative « reel force le déchiffrement même des pinnés » est
   hors périmètre v1.)*
6. **Hot-reload** : les workers surveillent `peer-rlevel.json` (+ `wg-peers.json`) →
   effet sur les **nouveaux** flux sans restart. Les flux en cours ne sont pas cassés.

## Application du mode `off` (nft, hors sbxmitm)

`sbxmitm-policyctl` régénère un dropin nft (`table inet secubox-toolbox-rlevel`) qui,
**avant** la règle DNAT→mitm des peers wg-toolbox, `return`/accepte les IP des peers en
mode effectif `off` → leur trafic n'est jamais redirigé vers les workers. Idempotent,
best-effort, ordre garanti (préfixe qui trie avant le fanout DNAT toolbox).

## Surface admin & self-service

- **Panneau `/rlevel`** (hybrid-dark, jeton `sbx_token`) : table des peers —
  nom, pubkey court, **mode effectif** (badge coloré off/passive/active/reel), **source**
  (peer-choisi / plancher / forcé), floor, **statut live** (dernier handshake wg,
  connecté/vu-il-y-a-N), compteurs de flux (stats sbxmitm par peer si dispo).
  Contrôles **admin** : régler `floor`, **forcer**/déverrouiller un mode par peer.
- **Portail peer** (servi via le tunnel uniquement) : le peer voit son mode effectif +
  règle son `chosen` dans `[floor, reel]`. Identifié par IP tunnel `10.99.x` → pubkey.
  Un peer ne peut PAS descendre sous son `floor` ni lever un `forced`.
- **API** : `GET /rlevel/peers` (admin), `POST /rlevel/peer/<pubkey>` (admin: floor/force),
  `GET /rlevel/me` + `POST /rlevel/me` (peer self-service, résout la pubkey depuis l'IP
  source). Actions privilégiées (écriture JSON + nft + signal workers) **déléguées** à
  `sbxmitm-policyctl` via sudo scopé (pattern [[feedback_webui_delegates_to_confined_ctl]]).

## CSPN / sécurité

- Écriture de politique = décision de sécurité → **audit append-only**
  `/var/log/secubox/audit.log` (qui, quel peer, ancien→nouveau mode, source).
- Le portail peer ne peut jamais **abaisser** l'inspection sous le `floor` ni contourner
  un `forced` → un peer ne peut pas se soustraire à l'inspection imposée.
- `off` est un vrai bypass réseau (nft) — réservé aux peers explicitement dé-inspectés
  par l'admin (ou choisi par le peer **si** le floor l'autorise, ce que le défaut
  `floor=passive` **interdit** : un peer ne peut pas se mettre en off tout seul).
- Fail-safe passive : jamais de trou d'inspection silencieux.

## Tests

- **rlevel.effective** (Go, pur) : `forced` prime ; `clamp(chosen, floor, reel)` ;
  peer absent → défauts ; ordre off<passive<active<reel ; fail-safe → passive sur JSON
  corrompu/absent.
- **résolution par flux** : IP→pubkey correct ; hôte splice-learned reste splice même
  en active/reel ; off n'atteint jamais le worker (couvert par le test nft).
- **nft off** : les IP des peers off sont exclues du DNAT→mitm, portée stricte, ordre
  avant le fanout ; un peer non-off n'est pas exclu.
- **ctl** : écrit le JSON, régénère le nft, idempotent, best-effort ; audit écrit.
- **API** : admin set floor/force ; peer self-service borné (ne descend pas sous floor,
  ne lève pas forced) ; auth par IP tunnel (une IP inconnue → 403).
- **panneau** : table + badges + self-service ; `sbx_token` ; pas de XSS (esc/délégation).
- **e2e (board)** : peer en passive (splice, pas de déchiffrement observé) → passe en
  active (déchiffrement + bannière) → passe en reel (un domaine bloqué) → forcé off par
  admin (bypass nft vérifié) — sans casser un hôte pinné (splice-learned).

## Risques connus

| Risque | Traitement |
|---|---|
| Déchiffrer un hôte cert-pinné → 502 | splice-learned par-hôte prime sur active/reel (garde-fou) |
| Peer se soustrait à l'inspection | portail borné par `floor` ; ne lève pas `forced` ; `off` interdit sous floor=passive |
| Politique illisible → trou d'inspection | fail-safe `passive` (jamais off/silence) |
| Hot-reload casse des flux en cours | n'affecte que les **nouveaux** flux ; flux établis intacts |
| nft off mal ordonné → DNAT toolbox l'emporte | dropin trié AVANT le fanout ([[feedback_nft_layered_dropins_persistence]]) |
| Action root depuis l'API | déléguée à `sbxmitm-policyctl` sudo scopé, jamais in-process |
| Usurpation d'IP tunnel pour régler le mode d'un autre peer | l'IP `10.99.x` est attribuée par wg (chiffré/authentifié par pubkey) — pas d'usurpation intra-tunnel ; le mapping IP→pubkey vient de wg lui-même |

## Hors périmètre (YAGNI v1)

Politique par **utilisateur** (login) en plus du peer ; `reel` forçant le déchiffrement
des hôtes pinnés ; quotas/horaires par peer ; per-flow (vs per-peer) ; historique/rollback
de politique au-delà de l'audit append-only. Cf. [[project_pending_features_2026-06-26]]
(interceptor temps réel, replay multi-device) pour les features connexes déjà au backlog.
