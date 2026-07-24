# Task 4 Report — sbxmitm-policyctl

Module : `secubox-toolbox`
Branche : `feat/rlevel-per-peer`

## Statut

COMPLETE — 21/21 tests passing.

## Fichiers créés

1. **`packages/secubox-toolbox/sbin/sbxmitm-policyctl`** (bash, `set -euo pipefail`, `jq` pour le JSON)
   - Sous-commandes : `set-floor <pubkey> <mode>`, `force <pubkey> <mode|none>`,
     `set-chosen <pubkey> <mode>`, `set-default <mode> <floor>`, `list`.
   - Écriture atomique de `peer-rlevel.json` : shadow-write (`<file>.shadow`) puis `mv -f`
     (rename atomique, même filesystem) — le rename lui-même est le signal de hot-reload
     pour les workers Go (`PeerPolicy` poll le mtime, cf. `cmd/sbxmitm/rlevel.go`).
   - Validation AVANT toute écriture : mode invalide ou pubkey absente de
     `wg-peers.json` → rc≠0, `peer-rlevel.json` intouché octet pour octet
     (`set-default` seul n'exige pas de pubkey).
   - `set-chosen` clamp côté serveur la valeur au floor du peer (miroir du futur
     garde-fou API peer), jamais en dessous.
   - Calcul du mode effectif (`forced ?? clamp(chosen, floor, reel)`) reproduit en `jq`
     (miroir exact de `effective()`/`rebuildLocked()` en Go) pour déterminer les peers
     dont l'IP doit être exclue du DNAT→mitm.
   - Régénère `NFT_D/secubox-toolbox-rlevel.nft` (`table inet secubox-toolbox-rlevel`,
     `chain prerouting { type nat hook prerouting priority dstnat - 1; ... }` —
     priorité UNE unité avant le fanout DNAT toolbox `priority dstnat`) puis
     `nft -f` (sauté sous `DRYRUN=1`). Set vide → aucune ligne `ip saddr` (table quasi-vide).
   - Audit : une ligne JSON append-only par mutation dans `AUDIT_FILE`
     (`ts` RFC3339 UTC, `module`, `action`, `pubkey`, `old`, `new`).
   - Chemins env-overridable pour les tests (`RLEVEL_FILE`, `WG_PEERS`, `NFT_D`,
     `AUDIT_FILE`, `DRYRUN`) ; en production (euid 0, sans `SBXMITM_POLICYCTL_TEST`)
     les env sont ignorées et les chemins figés en dur (parade anti env-injection,
     même posture que `secubox-macroctl`).
   - Ne touche jamais un parent partagé (`/run/secubox`, `/etc/secubox`,
     `/var/log/secubox`) — seulement les fichiers/dirs qu'il possède.

2. **`packages/secubox-toolbox/tests/test_policyctl.py`** (pytest + subprocess bash, 21 tests)
   - Mutations : set-floor / force / force-none / set-chosen (+ clamp au floor) /
     set-default / list.
   - Atomicité : pas de fichier `.shadow` résiduel ; idempotence (2× la même
     commande → contenu JSON identique).
   - nft off-bypass : `force PK2 off` (10.99.1.6) → IP présente dans le dropin,
     10.99.1.5 absente ; `force PK2 none` → IP retirée ; set vide → pas de
     ligne `ip saddr` ; priorité `dstnat - 1` présente.
   - Validation : mode invalide → rc≠0 + JSON intouché (avant ET après un état
     préalable) ; pubkey inconnue → rc≠0 (set-floor et force) ; `set-default`
     ne requiert pas de pubkey.
   - Audit : une ligne par mutation, champs corrects, RFC3339 ; rien n'est
     append en cas d'échec de validation ; s'accumule sur plusieurs mutations.

## Vérifications

```
$ cd packages/secubox-toolbox && python3 -m pytest tests/test_policyctl.py -q
21 passed in 0.83s

$ bash -n packages/secubox-toolbox/sbin/sbxmitm-policyctl
(silence = OK)

$ ls -l packages/secubox-toolbox/sbin/sbxmitm-policyctl
-rwxrwxr-x ... sbxmitm-policyctl
```

Vérification manuelle additionnelle (hors pytest) : `force PK2 off` en DRYRUN
produit bien `peer-rlevel.json` (`forced:"off"`), le dropin nft avec
`10.99.1.6` et `priority dstnat - 1`, une ligne d'audit JSON, et `list` reflète
l'état ; `set-floor PK1 bogus` échoue (rc=1) sans toucher au JSON existant.

## Préoccupations / limites connues

- La syntaxe nft générée (`priority dstnat - 1;`) n'a pas pu être validée par
  `nft -c` dans ce sandbox (pas de `CAP_NET_ADMIN`/accès netlink) — seule la
  forme textuelle a été vérifiée contre la spec du brief et les autres dropins
  du paquet.
- `sbxmitm-policyctl` n'est pas encore packagé (sudoers, `debian/rules`,
  seed par défaut de `peer-rlevel.json`) — prévu Task 8 du plan.
- L'intégration nft réelle (application effective par le worker Go du dropin
  généré, contre du vrai trafic) reste à vérifier en Task 5/e2e board.

## Fix CRITIQUE off-bypass nft

**Bug confirmé (revue noyau)** : `sbxmitm-policyctl` générait le off-bypass
dans une table nat séparée (`table inet secubox-toolbox-rlevel`, `return`
sans nat). En nftables, un `return` émis depuis une chaîne d'une AUTRE table
nat ne fige pas la décision pour la chaîne DNAT de `table inet wg-toolbox`
(priorité `dstnat` = **-100**, pas 0) — le noyau évalue toutes les chaînes
nat par priorité et ne s'arrête que sur une vraie décision (`dnat`/`accept`/
`return` **dans la même chaîne**). Le fanout continuait donc à DNAT le
trafic des peers "off" vers le moteur mitm → invariant « off = jamais
déchiffré » violé.

**Fix appliqué** :
- `nftables.d/secubox-toolbox-wg.nft` et `secubox-toolbox-wg-fanout.nft` :
  déclarent chacun un named set `rlevel_off { type ipv4_addr; flags
  interval; }` dans `table inet wg-toolbox`, et prépendent
  `ip saddr @rlevel_off return` comme **première règle** de leur `chain
  prerouting` (même chaîne que le DNAT — le fanout flush+remplace
  intégralement `chain prerouting`, donc le bypass doit y être répété pour
  rester actif quand le fanout multi-worker est chargé).
- `sbin/sbxmitm-policyctl` : suppression totale de la génération de la table
  séparée (`NFT_DROPIN`/`table inet secubox-toolbox-rlevel`). `regen_nft`
  fait maintenant `nft flush set inet wg-toolbox rlevel_off` puis
  `nft add element inet wg-toolbox rlevel_off { <ips off> }` ; en DRYRUN=1
  ces commandes sont écrites (shadow+rename) dans `$RLEVEL_NFT_OUT`
  (nouvel env, verrouillé au même titre que les autres en prod root) au lieu
  d'être exécutées, pour rester observables en test. Si le set/table
  n'existe pas encore (dropins nftables.d pas encore chargés), la fonction
  logue via `err` et retourne 0 (`return 0`, pas de `set -e` qui casse
  l'appelant) — comportement best-effort, non bloquant.
- Commentaire de priorité inexact corrigé partout où il apparaissait dans
  `sbxmitm-policyctl` : `dstnat == 0` → `dstnat == -100` (le nouveau design
  n'a d'ailleurs plus besoin d'arithmétique de priorité puisque le bypass
  est dans la même chaîne).
- `tests/test_policyctl.py` : les 3 tests nft historiques sont réécrits pour
  vérifier le contenu de `RLEVEL_NFT_OUT` (`flush set inet wg-toolbox
  rlevel_off` / `add element ... { 10.99.1.6 }`, IP active absente, set vide
  → flush seul sans `add element`). Ajout de 2 tests structurels (finding
  Important) : `test_ctl_writes_rlevel_json_via_shadow_then_rename` (grep du
  pattern shadow+`mv -f` dans le script — les tests comportementaux
  d'atomicité existaient déjà : `test_no_shadow_file_left_behind`,
  `test_invalid_mode_*_leaves_it_untouched`) et
  `test_nft_dropins_place_off_bypass_in_same_chain_as_dnat` (les deux
  fichiers `.nft` déclarent le set et le `return` précède le `dnat` dans la
  même chaîne, plus aucune trace de l'ancienne table séparée).

**Vérifications** : `python3 -m pytest tests/test_policyctl.py -q` → 23
passed ; `bash -n sbin/sbxmitm-policyctl` → OK. `nft -c -f` non exécutable
dans ce sandbox (pas de `CAP_NET_ADMIN`/netlink) — validation limitée à
l'inspection textuelle contre la syntaxe déjà en usage dans ces mêmes
fichiers.

**Limite connue** : le fix suppose que `nftables.d/secubox-toolbox-wg.nft`
et/ou `-wg-fanout.nft` ont été chargés (boot / `nft -f`) avant tout appel à
`sbxmitm-policyctl` en prod — sinon le set `wg-toolbox rlevel_off` n'existe
pas encore et la mise à jour est silencieusement différée (loggée, non
fatale). Non testé end-to-end contre un vrai noyau/dropin chargé (Task 5/e2e
board, comme déjà noté plus haut dans ce rapport).
