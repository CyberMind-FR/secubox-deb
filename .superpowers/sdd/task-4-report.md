# Task 4 Report — macros.d/tor-exit plugin

## Files Created

- `packages/secubox-macro/macros.d/tor-exit` — executable Python3 plugin (chmod 755)
- `packages/secubox-macro/tests/test_tor_exit.py` — 3 TDD tests

## TDD Sequence

**Step 1 — Wrote failing tests** (`tests/test_tor_exit.py`): 3 tests covering grant/revoke/activate.

**Step 2 — Confirmed failure** (plugin absent):
```
FAILED tests/test_tor_exit.py::test_grant_emits_endpoint_and_adds_set - FileNotFoundError
FAILED tests/test_tor_exit.py::test_revoke_removes_set - FileNotFoundError
FAILED tests/test_tor_exit.py::test_activate_writes_state - FileNotFoundError
3 failed in 0.12s
```

**Step 3 — Implemented plugin** and created `macros.d/` directory.

**Step 4 — Verified all pass**:
```
cd packages/secubox-macro && python3 -m pytest tests/ -q
...........                                                              [100%]
11 passed in 0.39s
```
(8 macroctl tests + 3 tor-exit tests = 11 total)

## Self-Review

### nft Syntax Check

The plugin uses:
```python
rc = _nft("add", "element", *TABLE.split(), SET, "{", a.src_ip, "}")
```

With `TABLE="inet secubox_filter"` and `SET="secubox_macro_torexit"`, `TABLE.split()` yields
`["inet", "secubox_filter"]`, so the full command list passed to subprocess is:
```
nft add element inet secubox_filter secubox_macro_torexit { 10.10.0.2 }
```

This matches the nftables named-set element syntax: `nft add element <family> <table> <set> { <element> }`.
The revoke path uses `delete element` with the same structure. Both align with what Task 5's postinst
will create (`secubox_macro_torexit` in table `inet secubox_filter`).

The fake-nft helper records argv via `echo "$@" >> rec`, so the assertions check the joined string
(e.g. `"add element inet secubox_filter secubox_macro_torexit { 10.10.0.2 }"`).
All three assertions in `test_grant_emits_endpoint_and_adds_set` pass: `"10.10.0.2" in calls`,
`"secubox_macro_torexit" in calls`, `"add" in calls`. Similarly `test_revoke_removes_set` checks
`"delete" in calls` and `"10.10.0.2" in calls`.

### Env-var Names

All five overrides match the brief exactly:
- `TOREXIT_NFT` — fake nft binary path
- `TOREXIT_MESH_IP` — provider-side mesh IP
- `TOREXIT_STATE_DIR` — consumer-side state directory
- `TOREXIT_SET` — nft set name
- `TOREXIT_TABLE` — nft table (space-separated family + name)

### SPDX / Copyright

Both files carry the full CMSD-1.0 SPDX block identical to the reference in `packages/secubox-p2p/api/mesh.py`.

### No-Shell Guarantee

`_nft()` passes args as a list to `subprocess.run` — no `shell=True`, no string interpolation of
user-controlled input.

### Executable Bit

`macros.d/tor-exit` is `chmod 755` — confirmed by `ls -la` output.

## Concerns

None. Implementation is a faithful transcription of the brief. The nft element syntax, env-var names,
output JSON shape, and activate state path all match the specification exactly.

---

## Security Review Fixes (review #771)

### FIX 1 — CRITICAL path traversal in `activate` (line 70-71)

**Problem**: `sid = cred.get("service_id", "unknown")` fed untrusted input directly into
`os.path.join(STATE_DIR, f"{sid}.json")`. An absolute path like `/etc/cron.d/evil` discards
STATE_DIR entirely; a traversal like `../../etc/evil` escapes it. Running as root this is a
direct root write primitive.

**Change** (`macros.d/tor-exit`, lines 70-71):
- Added `import re` to imports line 14.
- Replaced `sid = cred.get(...)` with:
  ```python
  raw_sid = str(cred.get("service_id", "unknown"))
  sid = re.sub(r"[^A-Za-z0-9_-]", "_", raw_sid)[:64] or "unknown"
  ```
- Strips all chars that are not `[A-Za-z0-9_-]` (eliminates `/`, `.`, whitespace, etc.), bounds to 64 chars.
- Result: `os.path.join(STATE_DIR, f"{sid}.json")` can only produce a path inside STATE_DIR.

**Without fix**: `os.path.join("/var/lib/secubox/macro/active", "../../etc/evil.json")` →
`/etc/evil.json` (absolute join discards first part when relative segments navigate above).
Actually Python's `os.path.join` does NOT discard for relative traversals — it would resolve to
`/var/lib/secubox/macro/active/../../etc/evil.json` = `/var/lib/secubox/etc/evil.json`, which still
escapes the intended `active/` leaf. The absolute path case (`/etc/cron.d/evil`) does fully discard.
Both cases are eliminated by the sanitize.

### FIX 2 — `socks_port` ValueError crash + no bounds (lines 47-52)

**Problem**: `port = int(params.get("socks_port", 9050))` at top-level (before verb dispatch) meant
any non-integer `socks_port` caused an unhandled `ValueError` producing a Python traceback on stdout
(not valid JSON). Also affected activate/revoke unnecessarily; no bounds check.

**Change** (`macros.d/tor-exit`):
- Removed top-level `port = int(...)` line (was after `params = json.loads(...)`).
- Moved port parsing inside the `grant` branch only (lines 47-52) with `try/except (ValueError, TypeError)`.
- Added `if not (1 <= port <= 65535): raise ValueError("port out of range")`.
- On failure: emits clean JSON `{"error": "invalid socks_port: ..."}` and returns 4.

### FIX 3 — revoke silently swallowed nft errors (lines 63-65)

**Problem**: `_nft("delete", ...)` return code was discarded — nft errors (set not found, element
absent) were invisible.

**Change** (`macros.d/tor-exit`):
- Captured rc: `rc = _nft("delete", ...)`
- Added: `if rc != 0: sys.stderr.write(json.dumps({"warn": "nft delete non-zero ..."}) + "\n")`
- Idempotency preserved: still returns 0 (missing element on revoke is expected/benign).
- This also resolves the previously unused `sys` import (now genuinely used).

### Adversarial tests added (`tests/test_tor_exit.py`)

Three new tests added after `test_activate_writes_state`:

1. **`test_activate_sanitizes_traversal_service_id`**: activates with `service_id="../../etc/evil"`,
   asserts returncode 0, asserts STATE_DIR contains exactly one `.json` file, asserts filename
   contains no `/` or `..`, asserts sanitized name is `______etc_evil.json`.

2. **`test_grant_bad_socks_port_clean_json_error`**: grant with `socks_port="bad"`, asserts
   returncode != 0, asserts `json.loads(r.stdout)["error"]` contains `"socks_port"` (clean JSON,
   no traceback).

3. **`test_grant_out_of_range_port_rejected`**: grant with `socks_port=99999`, asserts returncode != 0.

### pytest output (all 14 tests)

```
14 passed in 0.48s
```
(11 existing + 3 new adversarial = 14 total)
