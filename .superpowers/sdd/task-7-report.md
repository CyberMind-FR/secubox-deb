# Task 7 report — Tor enhancement Phase 1 — webui `#tor` tab

**Status:** DONE

**Branch:** `feature/tor-enhancement-phase1`
**Commit:** `b8d4e1b6` — `feat(toolbox): #tor tab — exit-country, Tor-VPN clients, obfs4 bridges, emancipate, .onion list + DNS status`
**File touched:** `packages/secubox-toolbox/www/toolbox/index.html` (only file, as instructed) — 355 insertions / 2 deletions.

(Note: this file previously held an unrelated stale Task-7 report from a different plan/openclaw dashboard — overwritten per instruction.)

## Panels added (inside the existing `#panel-tor` section, below the Tor-egress switch card, same P31-light skin)

1. **Exit-country** — `<select multiple>` populated from a curated static ISO 3166-1 alpha-2 list (`ISO_COUNTRIES`, ~72 countries, French labels, sorted). "Sélection actuelle" kv line + fail-closed warning banner (`StrictNodes 1` = no traffic if no exit exists in the chosen countries). Wired to `GET/POST /api/v1/toolbox/exit_country`.
2. **Tor-VPN clients** — kind selector (ip/cidr/mac) + selector input + add button; table with per-row 🗑 remove. Prominent IPv6 warning banner (v4-only tunnel, advise disabling IPv6 on routed clients/RA). Client-side heuristic (selector contains `:` and kind≠mac) short-circuits with a clean IPv6-specific message before hitting the API; the error path also recognizes a `:`-selector 400 and rewords it, since the backend's generic `"invalid kind/selector"` detail isn't IPv6-specific. Wired to `GET /vpn/clients`, `POST/DELETE /vpn/client`.
3. **obfs4 bridges** — paste-a-line input + add; list with per-row remove; hint pointing to Tor Browser moat / bridges.torproject.org. Wired to `GET /tor/bridges`, `POST/DELETE /tor/bridge`.
4. **Emancipate** — "🚀 Publier en .onion" button → `POST /api/v1/exposure/tor/emancipate_webui` (cross-module, JWT-gated); shows the returned `.onion` (from `output.onion` / `tor.onion`) with a clipboard copy button.
5. **Hidden services + .onion-DNS status** — `GET /api/v1/tor/hidden_services` table (name / onion / local port / state) and `GET /api/v1/tor/onion_dns` kv (dnsport_up / forward_zone_installed / resolves), fetched together via `Promise.all`.

## Endpoints wired (confirmed against source, not guessed)

- Toolbox-native (same origin, cookie/vhost-gated exactly like the existing `torSet()`/`loadTor()` — `_require_tor_admin` blocks the public kbin vhost, no bearer needed): `/api/v1/toolbox/exit_country`, `/api/v1/toolbox/vpn/clients`, `/api/v1/toolbox/vpn/client`, `/api/v1/toolbox/tor/bridges`, `/api/v1/toolbox/tor/bridge`.
- Cross-module (nginx-routed, confirmed via each module's `nginx/*.conf` location block): `/api/v1/exposure/tor/emancipate_webui` (requires JWT — `Depends(require_jwt)` in `packages/secubox-exposure/api/main.py`), `/api/v1/tor/hidden_services`, `/api/v1/tor/onion_dns` (no auth required server-side, bearer sent anyway for consistency).

## Auth approach

Two helpers, matching two different auth realities found in the source:
- `Tj(path, opts)` — toolbox's own tor-* routes: `credentials: 'same-origin'`, no bearer (mirrors existing `torSet`/`torLeaks`/`loadFilters`).
- `Xj(base, path, opts)` — cross-module (exposure + tor): reads `localStorage.getItem('sbx_token')`, sends `Authorization: Bearer <token>`, redirects to `/login.html` on 401 — this is the same pattern used by `packages/secubox-exposure/www/exposure/index.html` (`token()`/`headers()`/`api()`), and matches the fleet-wide `sbx_token` convention (a wrong localStorage key produces a login loop on other modules).

## XSS / robustness approach

- Every backend-derived string rendered into `innerHTML` goes through the existing global `esc()` (declared later in the file but hoisted — safe, since `function esc(s){}` statements hoist ahead of all script execution): error messages (`d.__error`/`dns.__error`/`hs.__error`), country codes, VPN client kind/selector, bridge lines, hidden-service name/onion_address, the emancipated `.onion` address.
- No `onclick="fn('${…}')"` was introduced. Static buttons (apply/clear/add-client/add-bridge/emancipate) use `addEventListener` wired once near the bottom of the script. Per-row dynamic elements (VPN-client remove, bridge remove, onion copy) use `data-*` attributes + `.querySelectorAll(...).forEach(b => b.addEventListener(...))` immediately after each render — the exact idiom already used by the file's existing `loadSentinelC2()`/`c2Ignore()` pair.
- Grep confirms the only `onclick="…${…}"` occurrences left in the file are pre-existing (lines for `setLevel`, `loadClientDetail`, `resetClient`, the "tout afficher" toggle, `quarantine`, `loadAdsClient`) — none are part of this change.
- `switchTab('tor')` and the tab's "🔁 Refresh" button now call a new `refreshTorTab()` which loads all five new panels plus the existing egress state, so nothing is left stuck on `loading…` after a tab switch.

## Validation

- `node --check` on the extracted `<script>` block: **PASS**.
- `grep -n 'onclick="[^"]*\${'` across the whole file: only pre-existing matches, none in the new code region.
- Manual read-through confirms every dynamic value hitting `innerHTML` is `esc()`-wrapped; numeric fields (`local_port`) and boolean-derived static strings are not (not attacker-controlled free text, no escaping needed).
- Not deployed to a board — that is Task 9's scope, explicitly excluded here.

## Concerns / follow-ups for later tasks

- The exit-country panel does not show a "live exit relay country" via geoIP (no such endpoint exists in the backend); it instead points the operator at the existing "Vérifier l'IP de sortie" button in the egress card above. Documented simplification, not a missing wire-up.
- The IPv6-selector 400 from the toolbox API returns a generic `"invalid kind/selector"` detail (not IPv6-specific) — the client-side heuristic (colon-in-selector) covers the common case cleanly, but a genuinely malformed non-IPv6 selector will still show the generic backend message, which is correct behavior, just not IPv6-labeled.
- The pre-existing deep-link array (`if (['overview','clients','filtres','social','ads','reseau','config'].includes(initial))`) still excludes `tor` and `sentinel` — a pre-existing gap unrelated to Task 7, left untouched per the "only touch this file for this task's scope" instruction (flagging it here rather than silently fixing it).

## Files touched

- `packages/secubox-toolbox/www/toolbox/index.html` (extended, commit `b8d4e1b6`)
