# Task 4 report — Toolbox API: exit-country + Tor-VPN-client + obfs4-bridge CRUD

**Status:** DONE
**Branch:** feature/tor-enhancement-phase1 (verified, not switched)
**Commit:** `c848b7c6` — feat(toolbox): exit-country + Tor-VPN-client + obfs4-bridge API (validated, audited, reconcile-triggered)

## Module found + style

`packages/secubox-toolbox/secubox_toolbox/api.py` (4333→4557 lines) — the
toolbox FastAPI app, `router = APIRouter(...)` included by
`secubox_toolbox/app.py`. Read the whole file first: essentially every route
is `async def` (grepped — the handful of apparent non-async hits were just
stacked `@router.get(...)` decorators above one `async def`), including the
closest analogues, `admin_tor_on` / `admin_tor_off` (#683), which don't
shell out synchronously — they just flip a flag via `filters.set_filters()`
(open/write/os.replace, all fast local I/O) inside an `async def`. New
endpoints mirror that exactly: `async def`, no subprocess calls.

## Trigger mechanism mirrored (not invented)

`secubox-toolbox-tor.path` (systemd Path unit) watches
`PathModified=/etc/secubox/toolbox/filters.json` and fires
`secubox-toolbox-tor.service` → `sbin/secubox-toolbox-tor-reconcile` (root,
oneshot). `admin_tor_on`/`off` trigger it by calling
`filters.set_filters(...)`, which rewrites `filters.json`. My
`_trigger_reconcile()` calls `set_filters({})` (empty patch — same
tmp+rename/fallback write path, so it "touches" the file and fires the
watcher) without touching `tor_mode` or any other flag. The portal never
escalates privilege; the reconciler does all the nft/tor work as root,
exactly as before.

**Known limitation, not introduced by this task, flagged for awareness:**
`secubox-toolbox-tor-reconcile`'s `arm()` no-ops when the `toolbox_tor` nft
table already exists (`table_present && log "already armed — no-op"`). So
if Tor is already armed and an operator adds/removes an exit-country or
VPN-client entry, the reconcile fires but is a no-op — the new selector
won't apply until the next disarm→arm cycle. This is pre-existing reconciler
behavior; the brief scoped this task to `api.py` + tests only, so I did not
touch `sbin/secubox-toolbox-tor-reconcile`. Worth a follow-up issue if the
operator flow expects live-apply while armed.

## Endpoints added (all in `secubox_toolbox/api.py`, admin-gated via the
existing `_require_tor_admin()` — blocks the public `kbin.*` vhost, same as
`admin_tor_on/off`)

- `GET/POST /exit_country` → `/etc/secubox/toolbox/tor-exit-country.txt`
  (one validated ISO cc per line, uppercased, deduped; POST replaces the
  whole list; 400 + **no partial write** on any bad code).
- `GET /vpn/clients`, `POST /vpn/client`, `DELETE /vpn/client` →
  `/etc/secubox/toolbox/tor-vpn-clients.txt` (`kind:selector` lines,
  kind ∈ ip/cidr/mac; add/remove one at a time, dedup).
- `GET /tor/bridges`, `POST /tor/bridge`, `DELETE /tor/bridge` →
  `/etc/secubox/toolbox/tor-bridges.txt` (each line must fullmatch
  `^Bridge obfs4 [][A-Za-z0-9:._=+/, -]+$`, else 400).

All three state files already existed as consumption targets in
`sbin/secubox-toolbox-tor-reconcile` (`EXIT_CC_STATE`, `VPN_CLIENTS_STATE`)
— I reused those exact paths (bridges is new, following the same
`/etc/secubox/toolbox/tor-*.txt` convention) via
`SECUBOX_TOR_*_PATH` env-overridable module constants (same override
pattern as `filters.FILTERS_PATH`), which is also what the test suite
monkeypatches.

Validators are exactly the brief's spec (`_valid_cc`, `_valid_selector`)
plus `_valid_bridge` (added `[]` to the bridge charset since real obfs4
lines carry `iat-mode=` etc. but never brackets in practice — kept the
brief's given regex verbatim, no deviation).

State writes use the same atomic-tmp-then-in-place-fallback pattern as
`filters.set_filters` (`/etc/secubox/toolbox` is 0750; the aggregator user
may not be able to create a tmp file in the parent dir). No parent
directory permissions are touched — `Path.mkdir(parents=True, exist_ok=True)`
is a no-op when `/etc/secubox/toolbox` already exists (which it always does
once `filters.json` has been written once).

## Audit trail

`_tor_audit(action, target, request)` appends
`{ts RFC3339} secubox-toolbox operator={ip} action={action} target={target}`
to `/var/log/secubox/audit.log`, mirroring the existing local pattern in
`secubox_toolbox/escalate.py`'s `_audit()` (append-only, `mkdir(parents=True,
exist_ok=True)` on the log's parent only, never chmod). The toolbox module
has no JWT/user-identity plumbing on this router (auth happens upstream at
nginx/aggregator level) — no existing "operator" identity is extracted
anywhere else in `api.py` either, so `operator=` uses `request.client.host`
as the best available identifier, falling back to `"admin"` if unavailable
(e.g. under TestClient with no real peer).

## Tests

`packages/secubox-toolbox/tests/test_tor_vpn_api.py` — 12 tests: the
brief's 2 validator tests verbatim (`_valid_cc`, `_valid_selector`) + 1 more
for `_valid_bridge`, plus `TestClient(app)` endpoint-behavior tests (get
empty, post replaces, reject-bad-code leaves no partial write, reject
non-list, vpn add/dedup/remove round-trip, bad selector, bridge
add/remove round-trip, bad bridge line, audit-line-written). All state
paths and `_trigger_reconcile` are monkeypatched per-test via the brief's
`_load()` fixture (extended with `TOR_BRIDGES` + `_TOR_AUDIT_LOG`).

```
cd packages/secubox-toolbox && python3 -m pytest tests/test_tor_vpn_api.py -q
→ 12 passed
```

Full suite:
```
cd packages/secubox-toolbox && python3 -m pytest tests/ -q
→ 3 failed, 264 passed
   FAILED tests/test_bypass_sources.py::test_load_bypass_tagged_missing_source_skipped
   FAILED tests/test_media_stats.py::test_media_stats_shapes_donuts
   FAILED tests/test_media_stats.py::test_media_stats_fail_empty
```
Verified these 3 are pre-existing and unrelated: stashed `api.py` (keeping
the new test file aside) and reran — same 3 failures, 252 passed (252 + the
12 new = 264, exact match, confirming zero regressions from this change).

TDD discipline: wrote the test file first with all endpoints/validators
referenced but not yet implemented, confirmed collection-time `AttributeError`
(red) against the pre-change `api.py`, then added the implementation and
reran to green.

## Concerns

1. **Reconcile no-op-while-armed** (above) — pre-existing, out of this
   task's file scope, flagged for a follow-up issue rather than silently
   fixed.
2. **Audit `operator=` is an IP, not an authenticated identity** — the
   module has no JWT layer on this router; this is consistent with the
   rest of `api.py`'s Tor-admin endpoints (none extract a user identity),
   not a regression introduced here.
3. No board deployment performed — pure code + local unit tests, as
   instructed.

---

## Review fix (2026-07-09) — reject IPv6 VPN selectors

**Commit:** `6b1c7625` — fix(toolbox): reject IPv6 VPN selectors (backend is v4-only) — no false-success

Coordinator review found one real `api.py` bug (the other two findings —
bridge-wiring + arm-noop reapply — are Task 8 reconcile work, not touched
here).

**Bug:** `_valid_selector("ip"/"cidr", ...)` used bare
`ipaddress.ip_address`/`ip_network`, which accept IPv6 (`2001:db8::1`,
`2001:db8::/32`). But the backend `tor_vpn_src` nft set is `type ipv4_addr`
and `populate_vpn_clients` silently skips non-v4 — so an operator POSTing an
IPv6 client got `200 OK` + an audit line implying success while nothing was
enforced (false success). Tightened the validator to IPv4-only
(`.version == 4`), so v6 selectors now → 400 with no state write (honest,
matches the Phase-1 v4-only backend).

Added 2 tests: `test_vpn_selector_rejects_ipv6` (validator: v6 ip/cidr →
False) and `test_vpn_client_rejects_ipv6` (`POST /vpn/client` with v6 ip and
v6 cidr → 400, no state file created).

```
cd packages/secubox-toolbox && python3 -m pytest tests/test_tor_vpn_api.py -q
→ 14 passed
cd packages/secubox-toolbox && python3 -m pytest tests/ -q
→ 3 failed, 266 passed   (same 3 pre-existing failures, zero new)
```
