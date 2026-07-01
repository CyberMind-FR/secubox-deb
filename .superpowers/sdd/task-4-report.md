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
