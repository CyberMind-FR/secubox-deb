<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# P2P Service Registry ↔ Annuaire Catalog — Design

**Date:** 2026-06-30
**Status:** Approved (brainstorming) — ready for implementation plan
**Scope:** Milestone 1 of the "services propose a macro subsystem" vision.
**Related:** `2026-06-30-annuaire-miroir-trust-substrate-design.md`,
`packages/secubox/PUNK-EXPOSURE.md` (Peek/Poke/Emancipate), issue #766
(trustless federation, secubox-annuaire 0.2.0).

---

## 1. Problem

`https://admin.gk2.secubox.in/p2p/` has a **Service Registry** tab that shows
"No services registered". It is backed by a local-only JSON file
(`SERVICES_FILE`) with hand-registered `{name, port, protocol, description}`
entries. Meanwhile **secubox-annuaire 0.2.0** is the real, federated,
self-certifying **service catalog**: nodes publish signed `ServiceOffer`s
(`WAF mirror`, `Suricata IDS feed`, …), federate them trustlessly over the
Gondwana mesh, and manage `Subscription`s with auto/pending approval.

The two are disconnected. The operator wants the p2p Service Registry to be the
**operational console over the annuaire catalog**: see every offered service
(local + federated-from-peers), subscribe to remote ones through the
invite/approval workflow, and mark services locally active — with a one-click
"Auto register all".

This is the **horizontal first milestone** of a larger vision: *every service
should also propose a "macro subsystem" — a vetted, parameterized automation
that scripts access to it* (e.g. a Tor-activated node offers its Tor exit as a
service; an approved peer activates and routes through it). That macro layer is
**designed here but built in Milestone 2** (§7), so M1 stays forward-compatible
without shipping any provider-side code execution.

## 2. Goals / Non-goals

**Goals (M1):**
- p2p Service Registry renders a **live view** of the annuaire catalog (no
  duplication, no drift) merged with a thin local "activation overlay".
- "Auto register all" = **activate locals + subscribe to remotes** (respecting
  each offer's auto/pending approval mode) — it does NOT copy the catalog.
- Per-service actions: Request access (subscribe), Activate, and visibility of
  subscription state (not-subscribed / pending / approved) and approval mode.
- Existing hand-registered p2p-local services keep working (no regression).

**Non-goals (M1 — deferred to M2, §7):**
- No provider-side macro execution / grant hooks.
- No consumer-side activation hooks that actually configure transport.
- No new annuaire `ServiceOffer` model fields.
- No fix for the gk2→c3box reverse-federation timeout (tracked separately).

## 3. Architecture

```
                       ┌─────────────────────────────────────────┐
                       │ secubox-annuaire  (SOURCE OF TRUTH)       │
                       │  /run/secubox/annuaire.sock               │
                       │   GET  /services        (federated catalog)│
                       │   GET  /subscriptions   (my sub states)    │
                       │   POST /service/{id}/subscribe             │
                       │   POST /subscription/{id}/approve|reject   │
                       └───────────────▲───────────────────────────┘
                                       │ unix-socket HTTP + service JWT
                                       │ (annuaire_client.py)
   ┌───────────────────────────────────┴──────────────────────────┐
   │ secubox-p2p                                                    │
   │  activation.json  { service_id → {active, local_port,          │
   │                     subscription_id, activated_at} }  (overlay)│
   │  GET  /services             → live merge(catalog, subs, overlay,│
   │                                 legacy SERVICES_FILE)          │
   │  POST /services/auto-register                                  │
   │  POST /services/{service_id}/activate                          │
   │  POST /services/{service_id}/request                           │
   │  www/p2p/index.html  Service Registry tab (live, buttons)      │
   └────────────────────────────────────────────────────────────────┘
```

annuaire is read over **its own unix socket**, not the aggregator (annuaire is
deliberately not aggregator-served — own socket, own event loop). p2p never
caches the catalog; it owns only the activation overlay.

## 4. Components

### 4.1 `secubox-p2p/api/annuaire_client.py` (new)
A small client module — single responsibility: talk to the local annuaire.
- `get_catalog() -> list[offer]` — `GET /services` over `annuaire.sock`.
- `get_subscriptions(mine_did=None) -> list[sub]` — `GET /subscriptions`.
- `subscribe(service_id) -> {subscription_id, state}` — `POST
  /service/{id}/subscribe`. annuaire's `SubscribeRequest` requires
  `subscriber_did` + `subscriber_priv_hex`, so p2p subscribes **as the node**:
  it reads the node key from `/etc/secubox/secrets/annuaire/node.key` (both
  secubox-annuaire and secubox-p2p run as `User=secubox`; the key is 0600
  secubox, so a same-user sibling read is in-policy and the key never leaves
  the box — localhost unix socket), derives the DID, and passes both. annuaire
  stays unchanged.
- `whoami() -> did` — the local node's annuaire DID, derived from the same
  node key (for local-vs-remote offer classification).
- Transport: `httpx`/`urllib` over `transport=UnixSocket`. 3 s timeout. Never
  raises into the request path — returns `(data, error)` and the caller
  degrades gracefully (shows catalog-unavailable, never 500s the p2p UI).

### 4.2 Activation overlay — `activation.json`
Stored under p2p's data dir. Schema:
```json
{
  "<service_id>": {
    "active": true,
    "local_port": 9050,
    "subscription_id": "…hex… | null",
    "activated_at": "RFC3339"
  }
}
```
- `local_port` derived from the offer `endpoint` (parse host:port / URL) when
  activating; null if not derivable.
- Idempotent upsert keyed by `service_id`. Removing an offer from the catalog
  leaves a harmless orphan overlay entry (garbage-collected lazily on read:
  overlay entries with no matching catalog/legacy service are dropped from the
  response and pruned).

### 4.3 `GET /services` — live merge
Produces one row per service from three sources:
1. **annuaire catalog** offers → `{name, type: kind, provider, endpoint,
   approval_mode, service_id, source: "annuaire", scope}`.
2. **annuaire subscriptions** → attach `subscription_state`
   (not-subscribed / pending / approved / rejected) per `service_id`.
3. **activation overlay** → attach `active`, `local_port`.
4. **legacy `SERVICES_FILE`** → rows tagged `source: "p2p-local"`,
   `provider: "local"`, always `active`.
Provider classification: `provider == whoami()` → display `local`; else short
DID. Sort: local first, then by name.

### 4.4 Action endpoints
- `POST /services/auto-register` (JWT): iterate catalog.
  - local offer → overlay activate (derive port).
  - remote offer, not yet subscribed → `annuaire subscribe`; record
    `subscription_id`; state becomes `approved` (auto offers) or `pending`.
  - returns `{activated, requested, pending, already, errors}`.
- `POST /services/{service_id}/request` (JWT): subscribe to one remote offer.
- `POST /services/{service_id}/activate` (JWT): overlay `active=true`
  (+ `local_port`). Refuses if the service is remote and not `approved`.

### 4.5 UI — Service Registry tab (`www/p2p/index.html`)
- Keep columns: Service Name / Type / Provider / Port / Status / Actions.
- **Status** badge: `active` | `approved` | `pending` | `not-subscribed`.
- Header: existing **+ Register Service** plus new **Auto register all**
  (calls `/services/auto-register`, then `loadServices()`).
- Row actions by state:
  - remote & not-subscribed → **Request access**
  - remote & pending → disabled *awaiting approval*
  - approved/local & inactive → **Activate**
  - legacy p2p-local → existing **Unregister**
- **automatable** badge when the offer `kind` is in a known macro-kind set
  (forward hint only; the badge is cosmetic in M1).
- All API-derived strings escaped (existing `escapeHtml`).

## 5. Data flow (sequence)

```
operator opens /p2p/ → Services tab
  loadServices() → GET /p2p/services
     p2p → annuaire.sock GET /services, GET /subscriptions
     merge with activation.json + legacy → rows
  table renders catalog (local + federated), states, buttons

operator clicks “Auto register all”
  POST /p2p/services/auto-register
     local offers   → overlay.active = true
     remote offers  → annuaire subscribe (auto→approved | pending)
  reload → states update; auto offers immediately active-able
```

## 6. Error handling
- annuaire socket down → `/services` returns legacy rows + a
  `catalog_unavailable: true` flag; UI shows a non-blocking notice, never errors.
- subscribe failure (e.g. node not a MEMBER) → surfaced per-row in the
  auto-register `errors` array; other rows still process.
- overlay write failure → logged; read path tolerates a missing/corrupt file
  (treats as empty overlay).

## 7. Deferred — the macro subsystem (Milestone 2, designed here)

The vision: *a service proposes a macro subsystem for scripting/automating
access to it.* Concretely, forward-compatible with M1:

- **Offer model extension:** `ServiceOffer.macro` (optional) =
  `{kind, params, access_protocol}`. Optional ⇒ existing 0.2.0 offers stay
  valid; it rides inside the signed payload ⇒ federates trustlessly.
- **Vetted plugin catalog:** `/usr/lib/secubox/<pkg>/macros.d/<kind>` with a
  fixed verb contract `grant | activate | revoke`. Offers select a `kind` and
  pass typed `params`; they NEVER ship code (CSPN: no remote code execution).
  Each kind ships an **AppArmor profile** (`secubox-macro-<kind>`), enforce.
- **Grant/activate flow:**
  - provider `approve` → runs `macros.d/<kind> grant --subscriber <did>
    --pubkey <hex> --params …` → returns connection details (endpoint, cred).
  - consumer `activate` → runs `macros.d/<kind> activate --with <details>` →
    configures local transport.
  - `revoke` mirrors on unsubscribe/offer-revoke.
- **Reference kind (M2):** `tor-exit` — provider offers its Tor exit; on
  approval grants the subscriber a scoped SOCKS/onion route; consumer activates
  routing. Subsequent kinds: `wg-relay`, `dns-resolver`, `http-mirror`.
- **Audit:** every grant/revoke appended to `/var/log/secubox/audit.log`
  (append-only) per the CSPN journaling rule.

M1 ships none of this execution; it only renders the `kind` and an
"automatable" hint so the UI and catalog are ready for it.

## 8. Testing

- `annuaire_client` merge: catalog ⨝ subs ⨝ overlay ⨝ legacy → correct rows,
  states, local-vs-remote classification.
- `auto-register` classification: local→activate, remote-auto→approved,
  remote-pending→pending, already-subscribed→skipped, MEMBER-less→error row.
- overlay: idempotent upsert, orphan pruning, corrupt/missing file tolerance.
- catalog-unavailable degradation (socket down) → legacy rows + flag, no 500.
- legacy p2p-local coexistence (no regression).
- UI smoke: rows render, buttons map to the right state, strings escaped.

## 9. Open questions

- **OQ-1 (subscriber identity):** In M1, what annuaire identity does the p2p
  node subscribe AS? Options: (a) the node's annuaire genesis identity (the
  node IS the subscriber — clean for node-level service consumption), or (b) a
  per-operator identity. **Default: (a)** — the node's own DID/key
  (`annuairectl` already bootstraps it); subscribe is a node-level act. Revisit
  if per-user subscriptions are needed.
- **OQ-2 (local_port derivation):** offers whose `endpoint` is a bare path
  (not host:port) yield `local_port: null`; the row still activates but shows
  no port. Acceptable for M1.

## 10. Rollout
- Single package touched: **secubox-p2p** (new `annuaire_client.py`, overlay,
  3 endpoints, UI). annuaire unchanged.
- Version bump, build, deploy gk2 + c3box, verify the catalog (incl. the
  federated `WAF mirror` / `Suricata IDS feed`) renders and auto-register
  subscribes correctly.
