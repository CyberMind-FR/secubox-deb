# Task 3 Report — Wire endpoints in api/main.py

## Status: DONE

---

## Files Changed

### `packages/secubox-p2p/api/main.py`

| Change | Lines (approx) |
|--------|---------------|
| Import `registry, annuaire_client` added to existing `from . import mesh` | line 29 |
| `ACTIVATION_FILE = P2P_DIR / "activation.json"` constant added | line 46 |
| `init_dirs()` updated: wrapped `P2P_DIR.mkdir` in `try/except PermissionError`; also mkdir parents of `ACTIVATION_FILE` and `SERVICES_FILE` (enables monkeypatching in tests) | lines 64–74 |
| `GET /services` `list_services` replaced: now live-merges catalog+subscriptions+overlay+legacy via `registry.merge_services` | lines 838–851 |
| `POST /services/auto-register` added after `unregister_service` | lines 868–907 |
| `POST /services/{service_id}/request` added | lines 910–920 |
| `POST /services/{service_id}/activate` added | lines 923–939 |

### `packages/secubox-p2p/tests/test_services_endpoints.py`

New file: 3 test cases (verbatim from brief) + one adaptation:
- Added `_override_jwt` async stub + `app.dependency_overrides` wiring in fixture.
  **Reason:** the live secubox_core is installed in `/usr/lib/python3/dist-packages` and the real `require_jwt` validates tokens; the fallback no-op only applies when secubox_core is absent. The brief assumes a dev env without secubox_core. The override uses the standard FastAPI `dependency_overrides` mechanism and is correctly torn down with `yield`+`clear()`.

---

## Test Results

### Task tests only

```
cd packages/secubox-p2p && python3 -m pytest tests/test_services_endpoints.py -v
3 passed in 0.27s
```

### Full suite

```
cd packages/secubox-p2p && python3 -m pytest tests/ -v
32 passed, 1 warning in 0.80s
```

All prior tests (test_mesh.py ×21, test_registry.py ×5, test_annuaire_client.py ×4) remain green.

---

## Self-Review

### Correctness
- `GET /services` correctly returns `{"services": [...], "catalog_unavailable": true}` shape on catalog error.
- `auto-register` correctly distinguishes local (provider == local_did → set_active) vs remote (subscribe → set_subscription).
- `request` and `activate` correctly delegate to annuaire_client and registry.
- All three POST endpoints require JWT (`Depends(require_jwt)`).

### init_dirs() change
The `try/except PermissionError` on `P2P_DIR.mkdir` is safe: in production the directory exists (created by postinst), so the branch is never taken. The extra `ACTIVATION_FILE.parent.mkdir` is also a no-op in production since `ACTIVATION_FILE.parent == P2P_DIR`. In tests, both changes are essential for monkeypatching to work without touching the real `/var/lib/secubox/p2p`.

### Route ordering concern (DONE_WITH_CONCERNS note)
FastAPI matches `/services/auto-register` before `/services/{service_id}/...` because static path segments rank above parameterised ones. Verified correct ordering in the router by placing `auto-register` before the `{service_id}` routes.

---

## Concerns

None blocking. One note:

- **IDE Pylance diagnostics**: "Impossible de résoudre l'importation `api`" in the test file. This is a false positive — `conftest.py` injects the package root into `sys.path` at pytest collection time, which Pylance's static analyser doesn't see. All three runtime imports resolve correctly (verified by pytest).
