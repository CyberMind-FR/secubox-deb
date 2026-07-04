# Task 2 Report — Mesh-Exclusion Payload Builder + Publisher

**Status:** ✅ COMPLETE

**Commit:** `9be001ee` — feat(toolbox): mesh-exclusion payload builder + publisher (ref #806)

**Test Result:** 2 passed in 0.04s

## Summary

Implemented the complete Python module + CLI for #806 mesh-federation, following strict TDD:

1. ✅ Created failing test (`test_mesh_exclusion_publish.py`) — 2 test cases
2. ✅ Implemented module (`mesh_exclusion.py`) with:
   - `local_lists()` — reads + dedupes + sorts + caps 3 exclusion files
   - `build_payload(nid, lists)` — constructs signed blob
   - `content_hash(payload)` — blake2b-256 deterministic hash
   - `publish(payload, priv_hex, did, nid)` — annuaire socket POST
   - Helper functions: `_read_list()`, `_annuaire()`, `_atomic_write()`, `node_id()`, `_version()`
   - Constants: `FED_MAX=2000`, `ANNUAIRE_SOCK`, `SCOPE_PREFIX`, local/federated paths

3. ✅ Cleanup applied: Replaced obfuscated `_version()` with clean `import time; return int(time.time())`
4. ✅ Created CLI script (`secubox-toolbox-mesh-exclusion-publish`, chmod 755)
5. ✅ SPDX headers added to all 3 new files
6. ✅ Tests pass: 2/2

## No Concerns

All code transcribed exactly per brief; cleanup applied as instructed. Ready for Task 3 (sync-side consumer of these exports).

---

## Fix Report — Critical + Minor Review Findings (2026-07-04)

**Status:** ✅ COMPLETE

**Commit:** `b13314d7` — fix(toolbox): mesh-exclusion publish sends JWT bearer + fd-safe annuaire call (ref #806)

**Test command:** `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_publish.py -q`
**Result:** `4 passed in 0.05s`

### Critical fixed — publish() sent no JWT (401 forever)

`_annuaire()` called `POST /config/publish` on secubox-annuaire, which is
`Depends(_require_jwt)` — with no `Authorization` header every publish would
403/401 in production. Fixed by mirroring the deployed pattern in
`packages/secubox-p2p/api/annuaire_client.py` (`SERVICE_USER` env-overridable,
default `"admin"`, `_service_token()` calling `secubox_core.auth.create_token(SERVICE_USER)`
in a try/except returning `None` on any failure). `_annuaire()` now attaches
`Authorization: Bearer <token>` to both GET and POST when a token is
mintable; when `secubox_core` is unavailable (unit tests) it silently sends
no header, matching the mirrored module's documented behavior.

### Minor fixed — fd leak in `_annuaire()`

`c.close()` was only reached after a successful `r.read()`; any exception
between `_UnixHTTP(...)` and `read()` (e.g. `getresponse()` raising) leaked
the socket. Moved `c.close()` into a `finally:` block (itself exception-safe)
so the connection is always closed, while still swallowing all errors and
returning `None`.

### Tests added

`tests/test_mesh_exclusion_publish.py`:
- `test_annuaire_attaches_bearer_token_when_available` — monkeypatches
  `mesh_exclusion._service_token` → `"tok"` and `mesh_exclusion._UnixHTTP` →
  a fake connection capturing the `headers` dict passed to `.request(...)`;
  asserts `headers["Authorization"] == "Bearer tok"`.
- `test_annuaire_closes_connection_on_read_error` — fake connection whose
  `getresponse()` raises; asserts `close()` still ran and `_annuaire()`
  returned `None`.

No public names/signatures changed (`publish`, `local_lists`, `build_payload`,
`content_hash`, `_read_list`, `_atomic_write`, `FED_*`, `SCOPE_PREFIX`,
`FED_MAX` all untouched) — Task 3 imports remain valid.
