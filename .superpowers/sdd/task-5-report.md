### Task 5 report — Emancipate the webui `.onion`, standalone + persist-on-boot (Tor enhancement Phase 1)

**Status:** COMPLETE
**Branch:** `feature/tor-enhancement-phase1` (verified, not switched)

**Files changed:**
- `packages/secubox-exposure/api/main.py` (+107 lines)
- `packages/secubox-exposure/sbin/secubox-exposure-tor-reconcile` (new, executable)
- `packages/secubox-exposure/systemd/secubox-exposure-tor-reconcile.service` (new)
- `packages/secubox-exposure/tests/test_emancipate_webui.py` (new, 8 tests)

**Functions added to `api/main.py`:**
- `_hs_dir_exists(name)` — `(TOR_DATA / name).exists()`.
- `_load_emancipated()` / `_save_emancipated(services)` — thin wrappers over the existing `load_config()`/`save_config()` for the `emancipated` list.
- `_mesh_present()` — best-effort mesh detection (lazy `from api.mesh_egress import mesh_ip`), wrapped in try/except, returns `False` on any error (no wg-mesh iface, import failure, etc.).
- `emancipate_webui(federate=False)` — calls `_tor_add_sync(name="webui", local_port=9080, onion_port=80)` (keyword call — required so the brief's `**k`-only-lambda test stub works), records `{name:"webui", local_port:9080, onion_port:80, active:True[, onion:...]}` in the exposure config (replacing any prior `webui` entry). When `federate=True` **and** `_mesh_present()`, publishes via `_publish("webui", f"http://{onion}/", {...})` — the whole federation block is wrapped in `try/except Exception: pass`, so a mesh/annuaire hiccup can never raise out of or block the call. When `federate=False` (default/standalone), the federation block is skipped entirely — `_publish` is never invoked.
- `tor_reconcile_persist()` — iterates `_load_emancipated()`, skips any entry that isn't `active`, skips entries missing `name`/`local_port`/`onion_port`, skips any whose `_hs_dir_exists(name)` is already `True` (idempotency — never re-creates an existing HS dir, so the `.onion` survives reboots), and `_tor_add_sync`s the rest, collecting applied names. Each iteration is wrapped in try/except so one bad entry can't abort the reconcile of the others. Returns `{"success": True, "applied": [...]}`.

**Import added:** `from api.mesh_egress import _publish` at module top level (unlike the other `mesh_egress` call sites in this file, which import lazily inside their function bodies) — needed so `_publish` is a stable `main` module attribute the tests (and `emancipate_webui`) can reference/monkeypatch as `m._publish`.

**Endpoint added:**
- `POST /tor/emancipate_webui?federate=<bool>` (JWT-gated via `Depends(require_jwt)`). Handler is `async def`; offloads the blocking call via `await asyncio.to_thread(emancipate_webui, federate)`, following the module's `_apply_tor` thread-offload convention for blocking Tor mechanics on the shared aggregator loop. (Note: the pre-existing `/tor/add` calls `_tor_add_sync` inline without offload — an existing inconsistency, left untouched as out of scope; the new endpoint follows the safer offloaded pattern per the brief's explicit instruction.)

**Standalone vs federation handling:**
- Default `federate=False` → pure standalone: HS created, config recorded, **zero** annuaire calls. Verified by `test_emancipate_webui_standalone_skips_federation`.
- `federate=True` only calls `_publish` when `_mesh_present()` is also true (no mesh ⇒ no publish attempt at all). Verified by `test_emancipate_webui_federate_true_publishes_when_mesh_present`.
- Federation failures (annuaire down, etc.) are swallowed — `emancipate_webui` still returns `{"success": True, ...}`. Verified by `test_emancipate_webui_federation_never_raises`.

**Idempotency approach (persist-on-boot):**
- `tor_reconcile_persist()` gates every re-apply on `_hs_dir_exists(name)` — if the directory (and therefore the onion keypair) is already on disk, the entry is skipped untouched; `_tor_add_sync` (and therefore `systemctl reload tor`) is only invoked for genuinely-missing HS dirs. Verified by `test_reconcile_never_recreates_existing_hs_dir` and `test_reconcile_reapplies_active_only` (inactive `old` entry never re-added).
- New `sbin/secubox-exposure-tor-reconcile` — thin `exec python3 -c "...; m.tor_reconcile_persist()"`, mirroring the existing `secubox-hub` sbin one-liner style (root, needs torrc + `systemctl reload tor` privilege).
- New `systemd/secubox-exposure-tor-reconcile.service` — `Type=oneshot`, `After=tor.service network.target`, `Wants=tor.service`, `ConditionPathExists=/etc/secubox/exposure.json`, `WantedBy=multi-user.target`. No `.path` unit added: a path-unit watching `/var/lib/tor` or `/etc/tor/torrc` risks a self-trigger loop the moment the reconcile (or Tor itself) touches those paths; since the boot-time oneshot restores state after a reboot/reprovision and the reconcile is already idempotent (no-op when nothing is missing), the extra unit wasn't added. Flagged here in case the operator wants belt-and-suspenders re-triggering on live torrc edits.
- Not wired into `debian/rules`/`debian/control`/postinst — out of scope per the task's explicit file-touch constraint (main.py + new sbin/systemd/tests files only); packaging wiring is a follow-up task.

**Test output:**
```
cd packages/secubox-exposure && python3 -m pytest tests/test_emancipate_webui.py -q
........
8 passed, 5 warnings in 0.31s

python3 -m pytest tests/ -q
.................................................................
65 passed, 5 warnings in 0.42s
```
Confirmed red before implementation (all 8 new tests failed — `AttributeError: module 'api.main' has no attribute ...`). No pre-existing failures in the package's `tests/` directory before or after this change; no new failures introduced.

**Concerns / follow-ups:**
- `POST /tor/emancipate_webui` and `tor_reconcile_persist()` are not yet wired into `debian/rules`/`debian/control` (sbin script install, systemd unit enable in postinst) — packaging is a separate task.
- The pre-existing `/tor/add` endpoint calls `_tor_add_sync` inline on the event loop without `asyncio.to_thread` offload (same class of SPOF flagged elsewhere in this project for blocking aggregator handlers); left untouched since out of this task's scope, worth a follow-up issue.
- No `.path` unit for live-torrc-triggered re-reconcile (see idempotency section above) — boot-time-only for now.
- No board deployment performed (explicitly out of scope for this task).

**Commit:** `217628ce` — `feat(exposure): emancipate webui .onion (standalone federate-optional) + persist-on-boot reconcile`

Note: an earlier commit attempt (`135f4ab9`) accidentally swept up an unrelated pre-staged file (`.superpowers/sdd/task-4-report.md`, staged by a prior/different session in this worktree before this task started). That commit was soft-reset and redone scoped to only the 4 intended files; `task-4-report.md` is left as an unstaged modification, untouched, exactly as it was found.
