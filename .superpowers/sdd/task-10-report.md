# Task 10 report — FastAPI webui backend (`api/web.py`)

## Status: DONE

## Files
- `packages/secubox-meshtastic/api/web.py` (new)
- `packages/secubox-meshtastic/tests/test_web.py` (new, 13 tests)

## Commit
`c9ab0fa4` — `feat(meshtastic): FastAPI webui backend (ref #897)`

## Design
`web.create_app(cache, send_cb, ctl_cb) -> FastAPI`, matching the brief's
explicit dependency-injection signature (distinct from `secubox-profiles`'
zero-arg `create_app()`, which closes over module-level globals — profiles
was still studied as the pattern reference for `require_jwt` wiring,
validate-before-delegate, and test structure).

Routes, all `Depends(require_jwt)`, prefix `/api/v1/meshtastic`:
- `GET /status` → `cache.get()`
- `GET /nodes` → `cache.get().get("nodes", [])`
- `GET /messages` → `cache.get().get("messages_by_channel", {})`
- `GET /packets` → `{"census": ..., "channel_stats": ...}` from cache
- `POST /send {channel,text}` → `send_cb(channel, text)` (no validation —
  real-time action, no root, no config write)
- `POST /mode {mode}` → 422 if `mode not in config.MODES`, else
  `ctl_cb("set-mode", mode=mode)`
- `POST /grid {channel,grid}` → 422 if any `grid[i] not in config.GRIDS`,
  else `ctl_cb("set-grid", channel=channel, grid=grid)`

`require_jwt` imported from `secubox_core.auth` with the same dev-fallback
stub as profiles' `web.py` (dist-packages first, ImportError fallback).
`/channel` mentioned in the thin brief was NOT implemented — the detailed
task instructions (routes list) omit it, so I followed the more specific
spec rather than the brief.

## Tests (13, all pass)
JWT gating (real `require_jwt`, no override) on `/status` and on all 6
routes collectively; read routes return exactly the injected cache dict/sub-
keys and default to `[]`/`{}` on a bare cache; `/send` calls `send_cb` with
correct args and returns its result; `/mode` and `/grid` each get a
bad-value → 422-and-ctl-NOT-called test plus a good-value →
ctl-called-with-expected-args test; a grep-level guard (code lines only,
skipping comments/docstrings) confirms `web.py` never imports `subprocess`
or shells out directly.

## Full suite
`60 passed` (was 47 before this task, +13 new — no regressions).
No `meshtastic`/`paho` imports introduced anywhere in the new files.

## Concerns
None. One iteration needed: my first grep-guard test tripped on the word
"subprocess" appearing in my own docstring prose (not code) — narrowed the
test to skip comment/docstring lines and to look for concrete offenders
(`import subprocess`, `os.system`, `Popen(`) instead of loose substrings.

---

## Follow-up fix — daemon.py `main()` cross-task integration gap (ref #897)

### Status: DONE

### Problem
`daemon.py::main()` still had Task-8-era placeholders (`web.create_app(engine)`,
one arg) and stale `# Task 10: replace ...` comments. Once this task made
`api/web.py` importable with a real 3-arg `create_app(cache, send_cb, ctl_cb)`,
the `try/except ImportError` guard around `from . import web` no longer caught
anything — `main()` would import `web` successfully and then raise `TypeError`
calling `create_app(engine)` with the wrong arity. The webui was wired to
nothing reachable end-to-end.

### Fix (`packages/secubox-meshtastic/api/daemon.py`)
- Added module-level `_ctl_cb(verb, **kwargs) -> dict`: builds
  `["sudo","-n","/usr/bin/systemd-run","--wait","--pipe","--collect","--quiet",
  "/usr/sbin/secubox-meshtasticctl", verb, ...]`, mirroring
  `secubox-profiles/api/web.py::_run_ctl_json_argv`'s shape but run
  synchronously (`subprocess.run(..., timeout=30)`, no asyncio loop in
  daemon.main() to offload onto). Argv shape matches the REAL
  `api/ctl.py` argparse (positional args, not the brief's guessed `--mode`
  flag): `set-mode <mode>`, `set-grid <channel> --grid <csv>`. `api/ctl.py`
  today prints plain text, not `--json` (confirmed: no `--json`/`json.dumps`
  report path in ctl.py) — so `_ctl_cb` first *tries* a JSON-report parse
  (forward-compatible if ctl.py ever grows one) and otherwise derives the
  dict from `rc`/stdout/stderr: `{"status":"applied","output":...}` on
  rc==0, `{"status":"error","stderr":...}` otherwise. Unknown verb ->
  `{"status":"error","stderr":"ctl verb inconnu: ..."}` without shelling out.
- In `main()`: `send_cb(channel, text)` closes over `engine` — returns
  `{"status":"radio-absent"}` when `engine.radio is None` (never crashes),
  else calls `engine.radio.send_text(text, channel)` (note argument order:
  `RadioInterface.send_text(text, channel=0)`) and returns
  `{"status":"sent","channel":channel}`.
- `app = web.create_app(engine.cache, send_cb, _ctl_cb)`, served via
  `uvicorn.run(app, uds=SOCKET_PATH, log_level="warning")`.
- `import uvicorn` moved inside the same `try/except ImportError` as
  `from . import web`, so the cache-refresh-only fallback path still
  degrades gracefully if either dependency is genuinely absent — safety net
  preserved, just no longer masking a real `TypeError`.
- Removed both stale `# Task 10: replace with uvicorn UDS serve of api.web`
  comments (now resolved).

### create_app call line
```python
app = web.create_app(engine.cache, send_cb, _ctl_cb)
```

### Verify
- `python -c "import ast; ast.parse(open('packages/secubox-meshtastic/api/daemon.py').read())"` → parses.
- `pytest tests/ -q` → `60 passed` (unchanged — `main()` remains untested by
  design, no device/UDS in CI).

### Concerns
None new. `main()` stays outside test coverage on purpose (no real serial
device or UDS bind in CI); correctness here rests on parse-check + matching
`api/ctl.py`'s actual (not hypothetical) argparse surface and `api/web.py`'s
actual (tested) `create_app` signature.
