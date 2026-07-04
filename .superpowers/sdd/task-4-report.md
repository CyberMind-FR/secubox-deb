# Task 4 Report: exposure API — GET/POST /exposure/{vhost} + apply

## Status
COMPLETE

## Commit Hash
`3c08acf4` — feat(exposure): /exposure/{vhost} get+set with fail-safe apply + audit (ref #793)

## Test Summary
3 passed (`tests/test_exposure_api.py`): POST writes snippet + returns record, GET reflects
written state, POST rejects invalid `reach` with 422.

## Blocking Concerns
None for the implementation itself. Two environment notes worth flagging:

1. **Local sandbox permission quirk (not code-related):** on this dev worktree host,
   `/var/lib/secubox` is `0750 secubox:secubox`, and `api/main.py`'s pre-existing
   module-level `DATA_DIR.mkdir(parents=True, exist_ok=True)` (line ~52, predates this
   task) raises `PermissionError` on import when run as the non-root worktree user. I
   ran the test command via passwordless `sudo` (already provisioned in sudoers) to get
   past it; no repo files or permissions were modified to work around it. Whoever runs
   this in CI/on the board as `secubox`/root won't hit it.
2. **Pre-existing test-order leakage:** running the whole `tests/` directory
   alphabetically (`test_exposure_api.py` before `test_reach.py`) makes
   `test_reach.py::test_snippet_path` fail, because `test_exposure_api.py`'s fixture
   reloads `api.reach` with a monkeypatched `EXPOSURE_SNIPPET_DIR` and nothing restores
   the module-level `SNIPPET_DIR` afterward. Running either file alone, or
   `test_reach.py` before `test_exposure_api.py`, passes cleanly. This is inherent to
   the reload-based test pattern from tasks 2/3, not introduced here, and out of this
   task's scope. The brief's specified command (`pytest tests/test_exposure_api.py -q`)
   is unaffected and passes 3/3.

## Implementation Summary

### Files Modified
- `packages/secubox-exposure/api/main.py`:
  - Added `Literal` to the `typing` import, `timezone` to the `datetime` import, and
    `from api import reach as _reach` (matching the file's existing `from api.X import Y`
    style used elsewhere for `mesh_egress`).
  - Added `ExposureSet` pydantic model (`reach: Literal["localhost","lan","wan"]`,
    `mesh: bool = False`, `tor: bool = False`).
  - Added `_reload_nginx()` — runs `nginx -t`, then `systemctl reload nginx` on success;
    fail-safe (catches all exceptions, returns `False`, never raises).
  - Added `_audit_exposure(vhost, rec, user)` — appends a line to
    `/var/log/secubox/audit.log` (best-effort, swallows `OSError`).
  - Added `GET /exposure/{vhost}` — JWT-protected, returns `_reach.load_record(vhost,
    is_public_now=False)`.
  - Added `POST /exposure/{vhost}` — JWT-protected, body validated via `ExposureSet`
    (invalid `reach` → 422 automatically via pydantic `Literal`), writes the snippet via
    `_reach.write_snippet`, calls `_reload_nginx()`, audits, returns the new record.
  - Used the brief's code verbatim.
- `packages/secubox-exposure/tests/test_exposure_api.py` — new, brief's exact 3 tests.

### TDD Workflow
1. Wrote the failing test file first.
2. Ran it — got `PermissionError` from the pre-existing `DATA_DIR.mkdir` at import time
   (local sandbox quirk, see above), re-ran via `sudo` and confirmed the expected
   `AttributeError: ... has no attribute '_reload_nginx'` (red, as specified in the brief).
3. Implemented the endpoints/helpers per the brief.
4. Re-ran — 3 passed (green).
5. Committed with the brief's exact message.

## Concerns
None regarding correctness or scope. No files outside `packages/secubox-exposure/` were
modified; `reach.py` was not touched.

---

## Follow-up: test-isolation fix (2026-07-04)

### Status
DONE

### Problem
The concern #2 above ("Pre-existing test-order leakage") was confirmed as a real bug:
`_client`'s `monkeypatch.setenv("EXPOSURE_SNIPPET_DIR", ...)` followed by
`importlib.reload(api.reach)` permanently mutated the module-level `SNIPPET_DIR`
attribute — `monkeypatch`'s teardown restores env vars, not the effects of a `reload()`,
so the leak persisted into `test_reach.py::test_snippet_path` when running the full
suite alphabetically. Confirmed before the fix: `pytest tests/` → 1 failed, 23 passed.

### Fix
Test-only change to `packages/secubox-exposure/tests/test_exposure_api.py`: the
`_client` fixture no longer sets the env var or reloads modules. Instead it does
`monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path / "snip")` directly on the imported
`api.reach` module object — `monkeypatch.setattr` auto-restores the original attribute
at teardown, mirroring the safe pattern already used in `test_reach.py`. Removed the
now-unused `importlib` import. The three test functions were left unchanged; they still
assert against `tmp_path / "snip" / "z.example.conf"`, which still matches because
`api.reach.write_snippet` reads the module-global `SNIPPET_DIR` directly and
`api/main.py` calls it via `_reach.write_snippet(...)` (module-reference, not a
re-bound import), so the monkeypatched attribute is honored.

No production code (`reach.py` / `main.py`) was modified.

### Verification
Command (prefixed with `sudo -E` per the documented `/var/lib/secubox` host-permission
quirk — `DATA_DIR.mkdir` in `api/main.py` raises `PermissionError` for a non-root user
on this dev host, unrelated to this fix):

```
cd packages/secubox-exposure && sudo -E env "PATH=$PATH" bash -c \
  'PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/ -q'
```

Result: **24 passed, 5 warnings in 0.29s** — 0 failures, leak confirmed gone.

### Commit
`fix(exposure): test fixture uses setattr not env-reload — no SNIPPET_DIR leak (ref #793)`
