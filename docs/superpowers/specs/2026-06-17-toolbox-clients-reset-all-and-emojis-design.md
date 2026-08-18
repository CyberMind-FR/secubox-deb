<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox #clients — reset-all (#634) + device/geo emojis (#635)

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox`
- **Issues:** #634 (reset-all), #635 (emojis) — one branch closes both
- **Status:** Design approved, pending implementation plan
- **Origin:** operator requests on the live `#clients` toolbox tab.

---

## 1. Goal

Two small, independent additions to the toolbox webui `#clients` tab (panel
`#panel-clients`, JS `loadClients()` → `GET /admin/clients/rich`):

- **#634 — Reset all:** a one-click "reset all clients" that applies the existing
  per-client reset to every client.
- **#635 — Emojis:** show a real device-type emoji, a country flag, and the
  hosting/ASN per client (the row currently has level/risk/status emojis and a
  hardcoded `device_emoji:"📱"` placeholder).

### Decisions (brainstorming)

| Question | Decision |
|---|---|
| Reset-all scope | **Per-client reset applied to all** — wipe events/consents/reports + all social-graph rows, zero scores, state=validated; **keep** client rows |
| Device source | latest UA from `consents.user_agent` → `avatar_analysis.classify_user_agent` |
| Geo source | `geo.lookup(ip)` (24h-cached) → `flag` + `asn_org` |

---

## 2. #634 — Reset all

**API.** New `POST /admin/clients/reset-all` in `api.py`:
- Gated by `_is_public_kbin(request)` → `HTTPException(403)` on the public kbin
  vhost (identical to the per-client `/admin/clients/{mac_hash}/reset`).
- Body: `for c in store.list_clients(): store.reset_client(c["mac_hash"]); social.wipe_mac(c["mac_hash"])` — reuse the **existing, tested** functions (per-client
  semantics: events/consents/reports wiped, score zeroed, state=validated, all
  `social_*` rows wiped; client row kept). Accumulate counts.
- Returns `{"ok": True, "clients_reset": N, "rows_deleted": M}`.

**UI.** A "↺ Reset all" button in the `#panel-clients` toolbar (next to the refresh
button), `onclick` → `confirm("Remettre à zéro TOUS les clients ? …")` → `POST`
`/admin/clients/reset-all` → on success `loadClients()` (+ optionally `loadSocial()`
so the graphs refresh). On the public kbin vhost the button may render but the POST
returns 403 (consistent with the per-client reset; the existing UI already lives
behind the auth-gated admin vhost for writes).

**Scale.** ≤200 clients (`list_clients` LIMIT 200), each reset is a handful of
DELETEs — acceptable as a synchronous loop. (A single bulk-DELETE SQL would be
faster but re-implements logic; reuse is safer and consistent.)

---

## 3. #635 — Device / geo emojis

**API.** Enrich each client in `admin_clients_rich()`:
- **Device:** fetch the most recent `user_agent` for the `mac_hash` from the
  `consents` table (it stores `user_agent` + `ts`); pass to
  `avatar_analysis.classify_user_agent(ua)` → use its `device_emoji` + `device`
  label. No UA → keep a generic fallback (`"📱"` / `"?"`). This replaces the
  hardcoded placeholder.
- **Geo:** `geo.lookup(client_ip)` → add `flag`, `country_iso`, `asn_org`.
  Cached 24h; for a private/LAN IP or miss, `lookup` returns blanks → render
  nothing for those fields.

A small helper `_latest_ua(conn, mac_hash) -> str` reads
`SELECT user_agent FROM consents WHERE mac_hash=? AND user_agent IS NOT NULL
ORDER BY ts DESC LIMIT 1`.

**UI.** In `loadClients()`'s row render, add the device emoji + country flag +
hosting. Keep it compact — e.g. a "Type / Geo" cell rendering
`${device_emoji} ${flag} <span title="${device} · ${asn_org}">${asn_org||''}</span>`
(escape any free-text like `asn_org`/`device`). The existing columns
(MAC/IP/state/niveau/score/last/Actions) stay; the new info slots in (either a new
cell or appended to the IP cell). Vanilla JS, consistent with the file.

---

## 4. Error handling

- Reset-all: wrap the loop so one client's failure (DB error) is logged and the
  loop continues; return the partial counts. Never 500 the whole request on a
  single-row error. The `_is_public_kbin` gate is checked first.
- Enrichment: `geo.lookup` and `classify_user_agent` are wrapped per-client; a
  failure yields the generic/blank fallback for that client, never breaks the list.
  `_latest_ua` returns "" on any query error.
- All free-text fields (`asn_org`, `device`) are HTML-escaped in the UI render
  (same `esc`/`escT` discipline as the #social/#filtres fixes).

## 5. Tests

`tests/test_clients_reset_emoji.py` (in-memory sqlite + stubbed geo):
- **reset-all:** seed N clients + events + social rows; call the reset-all handler
  logic (or `store`/`social` reuse) → all clients' events/social wiped, scores 0,
  client rows still present; count returned. kbin gate → 403 (assert the public-host
  branch raises/returns 403).
- **device:** `_latest_ua` returns the most recent UA; `classify_user_agent` of a
  known iPhone UA → `device_emoji`/`device` as expected (reuse avatar_analysis).
- **geo enrichment:** with `geo.lookup` monkeypatched to return a known
  `{flag, country_iso, asn_org}`, the enriched client carries those fields; a
  lookup returning blanks → blank fields (no crash).

## 6. Rollout

Cosmetic + an admin action; no gating, no engine/nft/DNS impact, no shared-dir
changes. Ships in the next toolbox version. Reset-all is destructive but
operator-initiated, confirm-dialogged, and kbin-gated — same trust model as the
existing per-client reset.

## 7. Out of scope

- New device-classification infrastructure (reuse `avatar_analysis`).
- Bulk-DELETE SQL (reuse per-client functions).
- Per-client geo persistence (lookup-on-render, cached).
