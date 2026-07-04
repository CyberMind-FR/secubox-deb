# Task 5 Report: Packaging mesh-exclusion timers (#806)

**Date**: 2026-07-04  
**Status**: ✅ **COMPLETE**

---

## Summary

Successfully packaged the mesh-exclusion publish + sync CLI scripts as systemd timers with installation and enablement on postinst.

## Commit

**Hash:** `d6076912`  
**Message:** `feat(toolbox): package mesh-exclusion publish+sync timers (ref #806)`

---

## Changes Made

### 1. Created 4 systemd unit files

Under `packages/secubox-toolbox/systemd/`:

- `secubox-toolbox-mesh-exclusion-publish.service`
- `secubox-toolbox-mesh-exclusion-publish.timer`
- `secubox-toolbox-mesh-exclusion-sync.service`
- `secubox-toolbox-mesh-exclusion-sync.timer`

All unit files created with exact specifications from brief:

- Service units with `Type=oneshot`, `ExecStart` pointing to `/usr/sbin/` scripts
- Timer units with `OnBootSec`, `OnUnitActiveSec=30min`, `Persistent=true`, `RandomizedDelaySec=3min`
- Proper `After=` dependencies on `secubox-toolbox.service` and `secubox-annuaire.service`

### 2. Modified `packages/secubox-toolbox/debian/rules`

Added 6 install lines in `override_dh_installsystemd` after autolearn timer lines:

- 2 lines to install the sbin scripts (publish, sync)
- 4 lines to install the systemd unit files (.service and .timer files)

Placement matches existing patterns for similar helpers (autolearn, tor, blacklist).

### 3. Modified `packages/secubox-toolbox/debian/postinst`

Added 4 enable+start lines inside the systemd conditional block:

```sh
systemctl enable secubox-toolbox-mesh-exclusion-publish.timer 2>/dev/null || true
systemctl start  secubox-toolbox-mesh-exclusion-publish.timer 2>/dev/null || true
systemctl enable secubox-toolbox-mesh-exclusion-sync.timer 2>/dev/null || true
systemctl start  secubox-toolbox-mesh-exclusion-sync.timer 2>/dev/null || true
```

Placement after autolearn timer enables, following existing convention with `2>/dev/null || true` guards.

---

## Verification

**Command executed:**

```bash
ls packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-*.{service,timer}
grep -c mesh-exclusion packages/secubox-toolbox/debian/rules packages/secubox-toolbox/debian/postinst
```

**Output:**

```
packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-publish.service
packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-publish.timer
packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-sync.service
packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-sync.timer
---
packages/secubox-toolbox/debian/rules:6
packages/secubox-toolbox/debian/postinst:4
```

**Result**: ✅ **PASSED**

- 4 unit files present
- rules: 6 matches (exactly required)
- postinst: 4 matches (exactly required)

---

## Integration Notes

- The 2 CLI scripts (`secubox-toolbox-mesh-exclusion-publish` and `secubox-toolbox-mesh-exclusion-sync`) from Tasks 2–3 exist and are correctly referenced by the service units
- Install paths follow exact pattern of nearby helpers (e.g., `debian/secubox-toolbox/usr/sbin/`, `debian/secubox-toolbox/lib/systemd/system/`)
- Postinst enable/start lines placed in same conditional block as existing timer enables
- No modifications outside `packages/secubox-toolbox/` per requirements

---

## Ready for Deploy

Task 5 is complete and committed. The systemd timer units are now:

1. Packaged into `secubox-toolbox.deb`
2. Installed at `dpkg install` time
3. Enabled and started in postinst

Next steps (manual, per brief Deploy section):

1. Cross-compile sbxmitm arm64 binary
2. Deploy sbxmitm binary to gk2/c3box/amd64
3. Rsync the 2 CLI scripts to all nodes
4. `systemctl daemon-reload` on all nodes
5. Verify timers fire: `systemctl status secubox-toolbox-mesh-exclusion-*.timer`

---

## #806 Final Whole-Branch Review — Fix Wave

**Date**: 2026-07-04
**Status**: ✅ **COMPLETE**
**Commit**: `c6257154` — `fix(toolbox): mesh-exclusion churn guard + never-raises + env overrides + fed-disabled enabled flag (ref #806)`

### Test command + result

```
cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_publish.py tests/test_mesh_exclusion_sync.py tests/test_filter_list_mesh_tag.py -q
```
```
..........                                                               [100%]
10 passed in 0.36s
```
(full `tests/` run: 209 passed, 3 pre-existing/unrelated failures confirmed present before this change via `git stash` — `test_bypass_sources.py::test_load_bypass_tagged_missing_source_skipped` (stale pre-#809 assertion shape) and 2x `test_media_stats.py` (`ModuleNotFoundError: secubox_core` in this local venv) — not touched, out of scope.)

### Fixes applied

1. **Publish churn guard** — `mesh_exclusion.py`: added `LAST_PUBLISHED` path + `_read_last_published()`/`_write_last_published()`; `publish()` now computes the content hash first and returns `True` without POSTing when it matches the last successfully-published hash, only persisting the new fingerprint after a successful POST. TDD: added `test_publish_skips_when_payload_unchanged` (red → green).
2. **`_atomic_write` + decode safety** — wrapped `_atomic_write`'s write/replace body in try/except (returns `False` on any error instead of raising); broadened `except OSError` → `except Exception` in `_read_list` and `node_id` so a non-UTF-8/decode error can't escape the best-effort boundary.
3. **Env overrides in `mesh_exclusion.py`** — `LOCAL_SPLICE`/`LOCAL_BYPASS`/`LOCAL_DISABLED`/`FED_SPLICE`/`FED_BYPASS`/`FED_DISABLED` now read `os.environ.get(...)` with the same var names as `policy.go`/`api.py` (`SECUBOX_SPLICE_LEARNED`, `SECUBOX_BYPASS_DYNAMIC`, `SECUBOX_FILTER_DISABLED`, `SECUBOX_FED_SPLICE`, `SECUBOX_FED_BYPASS`, `SECUBOX_FED_DISABLED`), same default paths, no divergence possible.
4. **Fed-disabled → `enabled` flag** — `api.py`: factored `_read_disabled_file(path)` and made `_load_disabled()` return the union of the local `MITM_FILTER_DISABLED_FILE` and `FED_DISABLED_FILE`, so a fleet-wide-disabled pattern (mesh-disabled row) now renders `enabled=False` in Filtres MITM, matching the R3 engine's `disabledLocal ∪ disabledFed`. TDD: added `test_fed_disabled_pattern_shows_enabled_false`.

No public names/signatures changed. Scope limited to `packages/secubox-toolbox/`.
