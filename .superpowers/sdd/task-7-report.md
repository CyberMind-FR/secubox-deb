STATUS: DONE
COMMIT: 692081f9af3cea70020ac132872ff23b77c007f1
TESTS: 16 passed (14 prior + 2 new) — `cd packages/secubox-p2p && python3 -m pytest tests/test_dht.py -v`
CONCERNS: none blocking. `.superpowers/sdd/task-5-report.md` shows as modified in `git status` but was not touched by this task (pre-existing uncommitted drift from an earlier session in this worktree) — left untouched/uncommitted, not part of this commit.

---

## Fix pass — issue #774 review findings (Task 7 hardening)

Reviewer found 4 real defects in the Task 7 iterative-lookup code in
`packages/secubox-p2p/api/dht.py`. All four fixed, plus one new regression
test.

### Fixes applied

1. **`_merge_contact` uncaught ValueError on malformed peer contacts**
   (Important, CONFIRMED). A single bad contact (bad hex `node_id_hex`, or
   `endpoint` without a `":"`) raised uncaught `ValueError`/`KeyError`/
   `TypeError` out of `iterative_find` → `find_peer`/`announce`, crashing the
   whole lookup for one malicious/buggy peer. Fixed by wrapping the parse
   (`bytes.fromhex`, `contact["did"]`, `self._parse_endpoint(...)`) in
   `try/except (ValueError, KeyError, TypeError): return` — the malformed
   contact is now silently discarded and the rest of the shortlist/lookup
   proceeds normally.

2. **Unbounded `shortlist`** (Important). A peer returning many fabricated
   "close" contacts could inflate `shortlist` indefinitely, forcing extra RPC
   rounds. Fixed: after merging all contacts from a round's replies,
   `shortlist` is sorted by `xor_distance` to `target_id` and truncated to
   `KAD_K` (`shortlist.sort(...); del shortlist[KAD_K:]`) before the
   round's convergence check.

3. **`asyncio.gather(*tasks)` without `return_exceptions=True`** (Important).
   A non-timeout exception from `send_fn` (relevant once real UDP lands)
   would propagate out of `gather` and abort the entire lookup. Fixed:
   `asyncio.gather(*tasks, return_exceptions=True)`, and the reply-processing
   loop now treats `isinstance(reply, BaseException)` the same as
   `reply is None` (skip and continue).

4. **`asyncio.get_event_loop()`** (Minor). Replaced with
   `asyncio.get_running_loop()` in `_rpc` — correct inside an already-running
   async context, avoids the deprecated/ambiguous fallback behavior of
   `get_event_loop()`.

### New regression test

`tests/test_dht.py::test_find_peer_survives_malformed_contact_in_reply` —
A knows only B; B knows C. C holds its own signed record locally (without
pushing it to B via `announce`, so B's `find_value` reply stays on the
"nodes" branch). B's `_reply` is wrapped so that any outgoing `"nodes"`
message gets a malformed contact
(`{"node_id_hex": "zz", "did": "did:bad", "endpoint": "noport"}`) spliced in
ahead of the real, good contact (C). Asserts `A.find_peer(C.did)` still
resolves C's verified record and does not raise.

Verified the test is load-bearing: temporarily reverted the try/except in
`_merge_contact` and confirmed this exact test fails with an uncaught
`ValueError: non-hexadecimal number found in fromhex() arg at position 0`
(see traceback origin `api.dht.DHTNetwork._merge_contact`); restored the fix
and the test (and the full suite) went green again.

### Test run

```bash
cd packages/secubox-p2p && python3 -m pytest tests/test_dht.py -v
```

Result: **17 passed** (16 prior + 1 new regression test), 0.05s. Full package
suite (`pytest tests/ -q`) also green: 66 passed.

### Commit

`fix(p2p): harden DHT iterative lookup — skip malformed contacts, cap shortlist, tolerate rpc exceptions (#774)`

### Concerns

None blocking. No public signatures changed; behavior change is strictly
additive hardening (skip-bad-contact, cap shortlist size, tolerate RPC
exceptions) — none of the 16 prior tests needed modification, all still pass
unchanged.
