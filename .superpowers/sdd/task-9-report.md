# Task 9 Report — secubox-meshtasticctl (privileged config CLI, ref #897)

(Note: this file previously held an unrelated stale Task-9 report from a
different plan — secubox-profiles waker/sleeper systemd units — overwritten
here since it did not belong to this plan.)

**Status:** Done.

## What was implemented

Files created, exactly the four named in the brief:

- `packages/secubox-meshtastic/api/ctl.py` — argparse CLI, `main(argv)`.
- `packages/secubox-meshtastic/sbin/secubox-meshtasticctl` — thin bash
  launcher (`cd /usr/lib/secubox/meshtastic && exec python3 -m api.ctl "$@"`),
  chmod +x.
- `packages/secubox-meshtastic/sudoers.d/secubox-meshtastic` — one scoped
  `systemd-run`-wrapped grant per verb shape, `visudo -c -f` → **`analyse
  réussie`**.
- `packages/secubox-meshtastic/tests/test_ctl.py` — 14 tests.

### Verbs (`set-mode`, `set-region`, `set-role`, `set-grid`, `set-psk`,
`apply-egress`)

Each: refuses non-root (`_running_as_root()` → rc=1, no write) → `config.load`
→ apply the change to a `dataclasses.replace` copy of `Config` → `_write_config`
(shadow file → `config.load(tmp)` validates it → `os.chmod` to match the
existing file's mode (or `0o640` if none existed) → `os.replace` atomic swap —
the double-buffer/4R shadow→validate→swap invariant from `.claude/CLAUDE.md`)
→ append a JSON audit line.

- `set-mode`/`set-role` are argparse `choices=` restricted to
  `config.MODES`/`config.ROLES` — an invalid value is rejected by argparse
  itself (`SystemExit`) **before** `config.load` is even called, so nothing
  is ever read or written.
- `set-grid <channel> --grid off,on`: comma-split, each token checked against
  `config.GRIDS` (rc=2, no write, on any bad token); unknown channel also
  rc=2, no write.
- `set-psk <channel> --secret <name>`: sets only the psk_secret **reference
  name** on that channel — no secret bytes are read, generated, or stored
  here, per the brief's explicit scope note.
- `apply-egress`: `gridpolicy.nft_egress_rules(cfg)` rendered into a
  self-contained `table inet secubox_meshtastic { chain egress { ... } }`
  drop-in (own base chain, `hook output`, `policy accept` on the chain
  itself — modeled on the existing `secubox-toolbox-wg.nft`/
  `secubox-threatmesh.nft` pattern already in the repo: it only ever *adds*
  narrow accept exceptions, and never overrides the separate DEFAULT DROP
  base chain that lives elsewhere). An empty rule list still writes a valid
  rule-less chain body — no allow rule is added, so DEFAULT DROP holds
  (the fail-safe the brief calls for).

### Paths (mirrors `secubox-profiles/api/actuate_paths.py`)

- Config: **always** `<root>/meshtastic.toml` (no real-vs-test branching —
  matches the brief's "override with `--root <dir>`" instruction literally,
  same as how `secubox-profilectl` derives `modules.d`/`profiles` under
  `--root` unconditionally).
- Audit log: real `/var/log/secubox/audit.log` only when
  `root == Path("/etc/secubox")`, else `<root>/audit.log`.
- Egress drop-in: real `/etc/secubox/nftables.d/secubox-meshtastic-egress.nft`
  only when `root == /etc/secubox`, else
  `<root>/nftables.d/secubox-meshtastic-egress.nft`.

### `_dump` (TOML serializer)

Small dedicated writer (not a line/section-preserving editor — `tomllib` on
Python 3.11 is read-only, as the brief notes) that reproduces exactly what
`config.load` reads: `mode`/`region`/`serial`, each `[[channel]]` (name, grid
list, psk_secret), optional `[shared_grid]`/`[on_grid]` (broker + enabled),
`[passive]` (role, packet_log). Verified round-trip: `test_dump_round_trips_edit`
edits one channel's grid and asserts every *other* field survives unchanged
through a full dump→reload cycle.

## TDD: RED → GREEN

RED (before `api/ctl.py` existed): `ModuleNotFoundError: No module named
'api.ctl'` on every test in `tests/test_ctl.py`.

GREEN after implementing `api/ctl.py`:
```
cd packages/secubox-meshtastic && python -m pytest tests/test_ctl.py -q
14 passed in 0.11s
```

One real bug caught during TDD: my first `apply-egress` "no broker" test
asserted the literal substring `"accept"` was absent from the drop-in, but
the base chain's own `policy accept;` declaration contains that word —
unrelated to any allow *rule*. Fixed the test to assert the absence of an
actual allow rule (`"ip daddr"` / `"meshtastic-on-grid"` comment) instead of
the word "accept", which is what the brief's invariant ("no accept RULE")
actually means.

## Full suite

```
cd packages/secubox-meshtastic && python -m pytest tests/ -q
47 passed in 0.19s
```
(33 prior + 14 new — matches the brief's "currently 33" baseline exactly.)

## Test coverage against the brief's checklist

- `set-grid` updates a known channel's grid (verified via `config.load`) —
  `test_set_grid_updates_known_channel`.
- `set-grid` rejects an unknown grid value, rc≠0, **no write** —
  `test_set_grid_rejects_unknown_grid_value` (asserts file content
  byte-identical before/after).
- `set-grid` rejects an unknown channel, rc≠0 —
  `test_set_grid_rejects_unknown_channel`.
- `set-mode turbo` → argparse `SystemExit` before any write —
  `test_set_mode_turbo_rejected_before_any_write` (asserts file content
  unchanged).
- `apply-egress` with no enabled on-grid broker → drop-in has no allow rule
  (DEFAULT DROP preserved) — `test_apply_egress_no_broker_writes_no_accept_rule`.
- `apply-egress` with an enabled broker → drop-in contains the broker allow —
  `test_apply_egress_with_enabled_broker_writes_allow_rule`.
- Root guard: `_running_as_root` → False ⇒ rc=1, no write —
  `test_root_guard_refuses_and_does_not_write`.
- `_dump` round-trips an edit — `test_dump_round_trips_edit`.
- Extra (not explicitly required but straightforward given the surface):
  `set-mode`/`set-role`/`set-region`/`set-psk` happy paths, `set-psk` unknown
  channel, and an audit-log content check.

## Files changed/created

- `packages/secubox-meshtastic/api/ctl.py` (new)
- `packages/secubox-meshtastic/sbin/secubox-meshtasticctl` (new, +x)
- `packages/secubox-meshtastic/sudoers.d/secubox-meshtastic` (new)
- `packages/secubox-meshtastic/tests/test_ctl.py` (new, 14 tests)
- `.superpowers/sdd/task-9-report.md` (this file, overwritten per instruction)

## Explicitly out of scope (flagging, not silently skipping)

- `debian/rules`/`debian/install`/`debian/postinst`/systemd units for this
  package do not exist yet at all (no `debian/install`, no `.service` file,
  no `postinst`) — packaging wiring for `secubox-meshtastic` as a whole
  (including installing `api/ctl.py`, the `sbin/` launcher, and the sudoers
  drop-in) is a separate, not-yet-reached packaging task; nothing in
  Task 9's brief asked for it, so I did not touch `debian/`.
- Secret **bytes** management (generating/storing the actual PSK) is
  explicitly out of scope per the brief — `set-psk` only ever writes the
  reference name.

## Concerns

- `set-region` and `--secret <name>` have no closed enum to validate against
  (unlike mode/role/grid) — they're accepted as opaque strings. Documented
  the wildcard-safety reasoning for this in the sudoers comment header
  (bounded by "never re-shelled, never used as a path/command" rather than
  "restricted to a known set"). Worth a second look if `set-region` ever
  needs a real region enum (e.g. from a Meshtastic region table) — currently
  none exists in `api/config.py` to validate against.
- No `debian/` packaging exists for this module at all yet, so this CLI is
  not reachable from an installed system until that task lands; confirmed
  this is expected (out of Task 9's scope) rather than an oversight.
