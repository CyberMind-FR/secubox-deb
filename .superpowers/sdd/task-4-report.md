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
