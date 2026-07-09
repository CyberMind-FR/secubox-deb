# Task 8 report — obfs4 bridges + reapply-when-armed

## 1. obfs4 bridge emission (`_emit_bridges`)

Added to `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`:

- `BRIDGES_STATE=/etc/secubox/toolbox/tor-bridges.txt`,
  `BRIDGES_DROPIN=/etc/tor/torrc.d/12-secubox-bridges.conf`.
- `_emit_bridges()` — reads the state file, keeps only lines matching
  `^Bridge obfs4 [][A-Za-z0-9:._=+/, -]+$`, emits `UseBridges 1` +
  `ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy` + the valid lines;
  empty/no valid lines → prints nothing (direct Tor). `set -euo pipefail`-safe
  (missing file → `return 0`, no unset-var reads).
- **Charset fix vs the brief's literal snippet**: the brief's regex
  (`[][A-Za-z0-9:._=+/,-]+`) omits the space character, but a real
  `Bridge obfs4 <addr> <fingerprint> cert=… iat-mode=…` line has spaces
  between tokens — the brief's own test fixtures contain that line and
  would never match with the literal regex. I aligned the charset with
  `secubox_toolbox/api.py`'s existing
  `_BRIDGE_RE = re.compile(r"^Bridge obfs4 [][A-Za-z0-9:._=+/, -]+$")`
  (note the space between `,` and `-`), so the reconciler's re-validation
  matches exactly what the API already accepted when it wrote the file —
  no format drift between the two validation layers. Verified with the
  brief's exact test payloads (see `tests/test_bridges.py`).
- Hidden dispatch `__emit_bridges) _emit_bridges "${2:-}"; exit 0 ;;` added
  before `*)`, mirroring the existing `__emit_exit_country` pattern.
- `arm()`: after the exit-country stanza, writes/removes `BRIDGES_DROPIN`
  from `_emit_bridges "$BRIDGES_STATE"`.
- `disarm()`: `rm -f "$BRIDGES_DROPIN"` added alongside the other drop-in
  cleanups.

## 2. control dependency

Added `obfs4proxy` to `packages/secubox-toolbox/debian/control`'s
**`Recommends:`** list (next to `tor`), not `Depends:`. Reasoning: the
brief offered either as acceptable, but `tor` itself is only a
`Recommends` in this package (the whole kbin-Tor-egress feature is
opt-in/ships-dark) — an obfs4 *pluggable transport* is meaningless without
`tor` present, so it inherits the same soft-dependency tier as its parent
rather than being pinned harder than the daemon it plugs into.

## 3. Step 5c — reapply-when-armed

Added `reapply()`:
1. Re-emits the exit-country stanza → `EXIT_CC_DROPIN` (write if non-empty,
   `rm -f` if empty).
2. Re-emits the bridges stanza → `BRIDGES_DROPIN` (same pattern).
3. `nft flush set inet toolbox_tor tor_vpn_src` (best-effort, `|| true` —
   see below) then `populate_vpn_clients`.
4. `nft flush set inet toolbox_tor tor_exempt` (`|| true`) then
   `populate_exempt`.
5. `systemctl reload tor 2>/dev/null || systemctl restart tor 2>/dev/null ||
   log WARN` — torrc drop-in changes need at minimum a reload to take
   effect; reload falls back to restart if tor doesn't accept a bare
   reload.

`main()`'s armed branch changed from `table_present && { log "already armed
— no-op"; exit 0; }` to `table_present && { reapply; exit 0; }`.

**Deviation from the brief's literal flush commands**: the brief shows the
two `nft flush set …` calls bare (no `|| true`). I added `2>/dev/null ||
true` to both, matching this script's established defensive style (every
other `nft`/`systemctl` call in `arm()`/`disarm()`/`populate_*` is guarded
the same way) and the file's stated constraint that `reapply` must be
"`set -euo pipefail`-safe (no abort on empty/bad input)". Without the
guard, a flush racing a concurrent disarm (table just torn down) would
abort the whole reconcile under `set -e` instead of degrading gracefully;
`populate_vpn_clients`/`populate_exempt` re-add elements to (now-empty)
sets regardless, so the guard costs nothing in the normal case.

### Disarm-safety of the API trigger path — verified, no defensive override added

Traced `POST /api/v1/toolbox/tor/bridge` (and the sibling exit-country/
VPN-client endpoints) → `_trigger_reconcile()` → `filters.set_filters({})`
→ `secubox-toolbox-tor.path` fires on the file touch → reconciler runs
`reconcile`.

`filters.set_filters(patch)` (`secubox_toolbox/filters.py:85`) starts from
`cur = get_filters(force=True)` — the **full merged on-disk dict**,
including whatever `tor_mode` is currently persisted — then only overwrites
keys that are present in `patch` and pass validation. `patch={}` has no
`tor_mode` key, so the loop never touches `cur["tor_mode"]`; the value
written back to `filters.json` is unchanged. `want_from_flag()` on the
reconciler side then reads that same on-disk `tor_mode`, unmodified.
**Conclusion: `set_filters({})` cannot clear/flip `tor_mode`** — an edit to
bridges/exit-country/VPN-clients while armed re-triggers `reconcile` with
`want=true` (unchanged), which now hits the `reapply()` branch instead of
disarming.

I deliberately did **not** add the brief's suggested fallback ("treat
table-present as want=true regardless of the flag"). `want_from_flag()`'s
existing behaviour — default `false` on any JSON parse error — is an
intentional fail-safe documented in the script itself
(`# default false on any parse error (fail-safe = off)`): if
`filters.json` is ever corrupted or unreadable, the reconciler should
**disarm**, not force-stay-armed. Overriding that with "table present ⇒
want=true" would silently invert a documented safety property for a
scenario (an API-triggered edit clearing `tor_mode`) that doesn't actually
occur. No change made there beyond the trace above.

### Testability change (sourcing guard)

The script's trailing `main "$@"` now only fires when executed directly:
```bash
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
```
This doesn't change production behaviour — the systemd unit
(`ExecStart=/usr/sbin/secubox-toolbox-tor-reconcile reconcile`) and
`postinst`/`prerm` all *execute* the script (shebang), never `source` it,
so `BASH_SOURCE[0] == $0` always holds there and `main` still auto-runs. It
lets the new reapply test `source` the script (loading real function
definitions), then redefine `table_present`/`nft`/`systemctl`/
`populate_vpn_clients`/`populate_exempt`/`_emit_exit_country`/
`_emit_bridges` as stubs, and call `main reconcile` explicitly in-process —
without touching a real `nft` table or `tor` service.

## 4. Tests (`tests/test_bridges.py`)

- `test_valid_bridge_emits_usebridges` — valid line → `UseBridges 1` +
  `ClientTransportPlugin` + the line, verbatim.
- `test_empty_emits_nothing` — blank input → empty stdout.
- `test_injection_line_skipped` — a `HiddenServiceDir /evil` line is
  dropped, the valid bridge line on the next line still emits.
- `test_missing_file_emits_nothing` — nonexistent state file → exit 0,
  empty stdout (matches `_emit_exit_country`'s existing contract).
- `test_reapply_reruns_emit_and_populate_helpers` — sources the script with
  `SECUBOX_FILTERS_PATH` pointing at a `{"tor_mode": true}` fixture, stubs
  `table_present` to report armed and stubs `nft`/`systemctl`/
  `populate_vpn_clients`/`populate_exempt`/`_emit_exit_country`/
  `_emit_bridges` to log to a marker file, calls `main reconcile`, and
  asserts all four helpers + a `systemctl reload|restart tor` call
  appear in the marker log — i.e. a second `reconcile` while armed
  re-runs the reapply path instead of no-op'ing.

### Red → green

Ran before the charset fix: 3/5 passed, 2 failed
(`test_valid_bridge_emits_usebridges`, `test_injection_line_skipped`) —
the brief's literal regex (missing space in the charset) rejected the
brief's own multi-token bridge line. After aligning the charset with
`api.py`'s `_BRIDGE_RE`: 5/5 pass.

```
$ python3 -m pytest tests/test_bridges.py -q
.....
5 passed in 0.07s
```

Full suite:
```
$ python3 -m pytest tests/ -q
... 3 failed, 271 passed, 437 warnings ...
FAILED tests/test_bypass_sources.py::test_load_bypass_tagged_missing_source_skipped
FAILED tests/test_media_stats.py::test_media_stats_shapes_donuts - ModuleNotFoundError
FAILED tests/test_media_stats.py::test_media_stats_fail_empty - ModuleNotFoundError
```
Same 3 pre-existing failures as the documented baseline (unrelated
modules); 271 passed = 266 baseline + 5 new. No new failures.

```
$ bash -n sbin/secubox-toolbox-tor-reconcile
(no output — syntax OK)
```

## 5. Scope check

Touched exactly: `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`,
`packages/secubox-toolbox/debian/control`,
`packages/secubox-toolbox/tests/test_bridges.py` (new). No other files
modified.

## 6. Concerns / follow-ups (non-blocking)

- `reapply()`'s `systemctl reload tor` assumes tor's systemd unit supports
  `reload` (SIGHUP re-read of torrc) for `UseBridges`/`ExitNodes` changes
  to take effect without dropping existing circuits; Debian's tor unit
  does define `ExecReload=/bin/kill -HUP $MAINPID` and Tor's control spec
  documents HUP as re-reading the torrc, so this should work, but it
  wasn't exercised against a live `tor` daemon in this sandbox (no board
  deploy per instructions).
- The obfs4proxy webui add/list/remove panel and the `/toolbox/#tor`
  bridges UI are explicitly out of scope per the brief's closing note
  (folded into Tasks 4/7 — `secubox_toolbox/api.py` already has the
  bridge CRUD endpoints/validation from a prior pass, confirmed present
  during this task's investigation but not modified).

## 7. Commit

`feat(toolbox): obfs4 bridges drop-in + reapply-when-armed (edits apply live)`
commit `7672b39d`.

---

# Review follow-up — two Critical fail-closed bugs fixed

Review found two Critical bugs in the fail-closed network path. Both fixed
in a second commit; only `sbin/secubox-toolbox-tor-reconcile` +
`tests/test_bridges.py` touched.

## CRITICAL 1 — `reapply()` opened a clearnet leak window on every call

**Bug:** `reapply()` did `nft flush set … tor_vpn_src` then
`populate_vpn_clients` (per-line `nft add element`) as SEPARATE netlink
transactions. Between the flush and a client's IP being re-added, that IP
was in neither `prerouting_vpn` (Tor redirect, gated on `@tor_vpn_src`) nor
`forward_vpn_killswitch`'s `drop` (also `@tor_vpn_src`-gated) → the forward
chain fell through to `policy accept` → a routed VPN client's forward
traffic passed DIRECT in the clear. Same window for `tor_exempt`.

**Fix:** atomic set swap. Added `_apply_set <setname>` (members comma-joined
on stdin) that emits a single `nft -f -` batch —
`flush set … ; add element … { m1,m2,… }` in ONE netlink transaction — so
the set is never momentarily empty. Refactored `populate_vpn_clients` and
`populate_exempt` into **collect mode**: they now echo the comma-joined,
identically-validated member list on stdout instead of doing per-line
`nft add`. Both `arm()` and `reapply()` now do
`populate_vpn_clients | _apply_set tor_vpn_src` and
`populate_exempt | _apply_set tor_exempt`. Empty member list → bare flush
(set legitimately empties). All `set -euo pipefail`-safe (`|| true` on the
nft calls; collect functions end on a `printf` returning 0).

Sub-points handled:
- `populate_exempt`'s own-public-IP `log` line now goes to **stderr**
  (`log … >&2`) so it never contaminates the stdout member list captured by
  the pipe.
- The dynamic spliced-hosts step (external
  `secubox-toolbox-tor-exempt-hosts`, which only **adds**, never flushes —
  so no atomicity window) was split into `populate_exempt_dynamic_hosts`,
  called AFTER the atomic base-set apply in both `arm()` and `reapply()`.

## CRITICAL 2 — torrc drop-ins written AFTER `systemctl restart tor`

**Bug:** in `arm()`, `systemctl restart tor` ran BEFORE the lines writing
`EXIT_CC_DROPIN`/`BRIDGES_DROPIN`, and `disarm()` always removes them — so
on every arm, tor (re)started reading `%include torrc.d/*.conf` with NO
bridges/exit-country present → a direct, unbridged connection (the exact
failure case obfs4 exists to defeat in a censored network), with nothing
reloading tor afterwards.

**Fix:** extracted `_write_torrc_dropins()` (emits both the exit-country
stanza via `_emit_exit_country` and the bridges stanza via `_emit_bridges`,
writing/removing `EXIT_CC_DROPIN` + `BRIDGES_DROPIN`) and call it BEFORE
`systemctl restart tor` in `arm()`. `reapply()` calls the same helper before
its `systemctl reload tor`. This fixes the new bridges ordering AND the
pre-existing exit-country ordering bug in one place, and removes the
duplicated inline blocks the reviewer flagged (Minor).

## Reasoning on the two design choices

- **Why a single `nft -f -` batch is atomic:** nftables applies one
  `nft -f` ruleset file as a single atomic transaction (all-or-nothing
  commit to the kernel). Putting `flush set` and `add element` in the same
  batch means the kernel never observes the intermediate empty-set state —
  there is no scheduling point where a packet could be evaluated against a
  half-updated set. Two separate `nft` invocations are two transactions
  with a real (arbitrarily long, under load) gap between them.
- **Why `_write_torrc_dropins` before the (re)start, not a post-hoc
  reload:** a post-restart reload would still leave a bootstrap window where
  tor dials out directly/unbridged; in a censored network that first
  unbridged attempt is precisely what gets the connection fingerprinted or
  blocked. Ordering the drop-ins first means tor's very first bootstrap
  already uses the bridges.

## Tests (adjusted)

`tests/test_bridges.py` now 6 tests (was 5): the 4 `_emit_bridges` tests
unchanged; the single old reapply test replaced by two:
- `test_reapply_writes_torrc_before_tor_reload` — stubs the helpers to an
  ordered marker log and asserts `_write_torrc_dropins`,
  `_apply_set tor_vpn_src`, `_apply_set tor_exempt`, and the dynamic-hosts
  step all ran, AND that `write_torrc_dropins`'s marker index precedes the
  `systemctl reload tor` marker index (stub-order proof of the CRITICAL 2
  fix).
- `test_reapply_uses_atomic_set_swap` — feeds a real `ip:10.0.0.5` VPN
  state file, stubs `nft` to capture args + stdin, and asserts the
  tor_vpn_src update went through `nft -f -` carrying a
  `flush set … tor_vpn_src` + `add element … tor_vpn_src { 10.0.0.5 }`
  batch, and that NO bare `flush set … tor_vpn_src` invocation was left
  standing (proof of the CRITICAL 1 fix — atomic, no empty window).

Both stub sets return 0 throughout because sourcing the reconciler
propagates its `set -euo pipefail` into the test harness.

```
$ python3 -m pytest tests/test_bridges.py -q
......
6 passed in 0.09s

$ python3 -m pytest tests/ -q
... 3 failed, 272 passed ...   # same 3 pre-existing (bypass_sources/media_stats), no new

$ bash -n sbin/secubox-toolbox-tor-reconcile
(no output — syntax OK)
```

`test_tor_switch.py::test_reconcile_populates_exempt_and_excludes_automap`
(greps the script for `tor_exempt`/`127.0.0.0/8`/`api.ipify.org`/
`scope link`/`10.19`) still passes — the collect-mode refactor preserved
all those tokens.

## Fix commit

`fix(toolbox): atomic nft set swap in reapply (no clearnet window) + write torrc drop-ins before tor restart`
