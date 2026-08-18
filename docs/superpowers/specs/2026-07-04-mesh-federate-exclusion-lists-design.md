<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mesh-federate the toolbox exclusion lists (#806) — design

**Issue:** #806 · **Date:** 2026-07-04 · **Status:** design

## Goal

Share the toolbox's **mutable** MITM-exclusion lists peer-to-peer across the
gondwana mesh (gk2/c3box/amd64) so every node benefits from what the others
learned (and what the operator disabled) — one fleet-wide exclusion control
plane, riding the **existing** signed ConfigBlob federation. No new sync
protocol.

## What federates (and what does not)

Federated (the 3 **mutable** files, one operator across the fleet):
- `splice-learned.txt` — autolearned cert-pinned splice hosts (suffix).
- `mitm-bypass-dynamic.conf` — autolearned bypass patterns (regex).
- `mitm-filter-disabled.txt` — operator "unchecked" patterns (#809).

NOT federated:
- Package **seeds** (`tls-splice-seed.conf`, `mitm-bypass-seed.conf`) — already
  byte-identical on every node via the `.deb`; federating them is redundant.
- Operator static `mitm-bypass.conf` — treated as node-local (out of scope v1;
  the operator adds it locally, and can promote to federation by learning).

**`disabled` semantics = union: disabled-anywhere ⇒ disabled-everywhere.**
Re-enabling is fleet-wide — clear it on the origin node and it lifts everywhere
on the next sync. This matches "one operator, one control plane." A node can
still *locally* disable a federated entry (adds to its own local disabled).

## Transport (reuse — no new protocol)

The annuaire directory already federates **signed, scoped, versioned ConfigBlobs**:
- `POST /config/publish` — publish a signed blob `{scope, payload, version}`.
- `GET /config?scope=<s>` — list current (non-revoked) blobs for a scope.
- `POST /config/revoke` — withdraw (publisher only).
- Blobs carry `author_pubkey`; consumers verify the signature before applying.

New scope: **`mitm-exclusion`**. Each node publishes exactly one current blob
(a new publish supersedes its prior version).

**Payload:**
```json
{ "node": "<node_id>",
  "splice":   ["api.anthropic.com", "..."],
  "bypass":   ["(.+\\.)?signal\\.org", "..."],
  "disabled": ["(.+\\.)?adform\\.net", "..."] }
```
Each list deduped + capped to `FED_MAX` (2000) entries. The blob is signed by
the node key; only blobs from MEMBER nodes with a valid signature are applied.

## Components

### 1. Publisher — `secubox-toolbox-mesh-exclusion-publish` (timer)
- Reads this node's LOCAL `splice-learned` / `mitm-bypass-dynamic` /
  `mitm-filter-disabled` (comment-stripped, deduped, capped).
- Skips publishing if the payload is byte-identical to the last one published
  (no-op churn guard; keeps a small `last-published.json` fingerprint).
- Signs + `POST /config/publish` scope=`mitm-exclusion`. Best-effort: a
  directory error is logged and retried next tick; never blocks.
- Cadence: `OnUnitActiveSec=30min` + `OnBootSec=8min`, randomized delay.

### 2. Sync — `secubox-toolbox-mesh-exclusion-sync` (timer)
- `GET /config?scope=mitm-exclusion` from the local directory (which already
  holds the federated blobs via log/config federation).
- For each blob: verify signature + MEMBER status; skip on failure.
- **Union** every node's `splice` / `bypass` / `disabled` (including this
  node's own published blob — idempotent). Dedup + cap.
- Atomically write (temp + `os.replace`) the 3 federated files:
  `/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt`,
  `…-fed-bypass.txt`, `…-fed-disabled.txt`. Only rewrite when content changed
  (mtime-stable → engine doesn't needlessly reload).
- Cadence: same as publisher, offset so a publish precedes the next pull.

### 3. Engine — `sbxmitm` (Go, PolicyOpts + reload)
- 3 new opts + defaults (env-overridable):
  `SpliceFederatedPath` → `…-fed-splice.txt`,
  `BypassFederatedPath` → `…-fed-bypass.txt`,
  `DisabledFederatedPath` → `…-fed-disabled.txt`.
- `spliceFed map[string]bool` — a THIRD splice source: `shouldSplice` returns
  true on `spliceSeed ∪ spliceLearn ∪ spliceFed` (never-set + disabled still
  win, unchanged).
- `bypassFedRe []bypassEntry` — a FOURTH bypass group in `matchesBypass`.
- Federated disabled is **merged into the effective disabled set**: the reload
  target for either the local or the federated disabled file rebuilds
  `p.disabled = local ∪ federated`. (Keep `p.disabledLocal` + `p.disabledFed`
  and recompute the union on either change to stay hot-reload-correct.)
- All 3 registered as `reload.Target`s (mtime hot-reload), same as #803/#809.

### 4. Webui — Filtres MITM
- `/admin/filter-control/list` also reads the 3 fed files, tagging those rows
  `mesh` (badge `🌐 mesh`). A `mesh` row is `editable:false` for delete (you
  delete it on its origin node) but the checkbox still works (local disable).

## Data flow

```
local autolearn / webui toggle → local files
  → publisher: sign payload → POST /config/publish (scope=mitm-exclusion)
  → [existing ConfigBlob federation propagates the blob to all nodes]
  → sync (each node): GET /config?scope → verify + union → write fed files
  → sbxmitm hot-reloads fed files → Decide() honours the fleet-wide union
```

## Error handling / safety

- **Directory unreachable** → publish/sync retry next tick; never blocks the
  engine (the engine reads whatever fed files exist).
- **Bad signature / non-MEMBER / malformed payload** → that blob is skipped;
  never applied. Untrusted input cannot poison the fleet lists.
- **Missing/empty fed file** → engine treats as no federated entries
  (fail-open on availability, identical to the existing lists).
- **Flood guard** → per-list `FED_MAX` cap on both publish and union; a
  looping/rogue node cannot grow the set unbounded.
- **Churn guard** → publisher skips identical re-publish; sync rewrites a fed
  file only when its content changed.
- **No seed/never override** → never-set (pure-trackers/fortknox) and ad-block
  precedence in `Decide` are unchanged; federation only adds to the same
  splice/bypass/disabled inputs.

## Testing

- **Go** (`policy_test.go`): fed-splice host → `splice`; fed-bypass regex host →
  `splice` (after ad-block, per #803 ordering); fed-disabled pattern suppresses a
  match that the seed would otherwise splice; union of local ∪ fed disabled.
- **Python**: publisher builds the correct capped/deduped payload from local
  files; sync unions N blobs + writes the 3 fed files; a blob with a bad
  signature is skipped; identical-payload republish is a no-op.
- **Integration** (2-node, on the live mesh or a harness): a pattern present only
  on node A's local list appears in node B's `…-fed-*.txt` after one
  publish+sync cycle, and B's engine then splices it.

## Scope / decomposition

Single spec. New work: the Go engine's 3 federated paths + union-disabled; the
Python publisher + sync services/timers; the webui `🌐 mesh` badge. Everything
rides the existing ConfigBlob federation — no new transport, no directory
schema change (just a new `scope` value).

## Out of scope / follow-ons

- Federating the operator **static** `mitm-bypass.conf` (v1 keeps it local).
- A federation **dashboard** (which node contributed which entry) — the `🌐 mesh`
  badge is the v1 surface.
- Revocation UX for a specific federated entry (v1: clear on origin → lifts on
  sync; `/config/revoke` withdraws a whole node's blob).
