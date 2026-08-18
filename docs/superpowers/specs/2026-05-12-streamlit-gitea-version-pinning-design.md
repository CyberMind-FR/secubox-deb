<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Streamlit Gitea Version Pinning — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#95](https://github.com/CyberMind-FR/secubox-deb/issues/95) (sub-project F of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#93](https://github.com/CyberMind-FR/secubox-deb/pull/93) (Gitea live), [#97](https://github.com/CyberMind-FR/secubox-deb/pull/97) (MetaBlogizer ingest patterns)

## Context

The Streamlit infrastructure on the MOCHAbin is already running:

- LXC `streamlit` (id 10.100.0.50, RUNNING)
- `/srv/streamlit/apps/` bind-mounted into the LXC (host↔LXC same path)
- 30 directory-form apps; 23 already have `.git/` (history is preserved locally)
- 3 active Streamlit instances on ports 8501–8506 (`yijing`, `wuyun_liuqi`, `bazi_calculator`)
- `secubox-streamlit` package with a FastAPI surface (`/api/v1/streamlit/apps/<name>`, `/deploy`, `/start`, `/stop`, `/logs`) and a `streamlitctl` CLI

What's missing (this sub-project):

- Centralised tracking in Gitea (today nothing publishes the Streamlit apps)
- Tag-based version pinning (`v1.0.0`, `v1.1.0`, …) per app
- A deploy path that clones a specific Gitea tag into `/srv/streamlit/apps/<name>/`
- Version surfacing in the existing API (`current_tag` field)

## Goal

Mirror the 30 directory-form Streamlit apps from `/srv/streamlit/apps/` into Gitea at `gandalf/streamlit-<app>` with `v1.0.0` on the initial state, and add a `--tag` flag to `streamlitctl deploy` that performs a **clone + replace in-place** with backup, restarting the app's running instance if any.

## Non-goals

- Multi-versions side-by-side (`/srv/streamlit/apps/<app>-v1.0.0/`) — explicitly rejected during brainstorming as too much state
- Container-per-version — same reason
- Webhook-triggered redeploy on Gitea tag push — separate sub-project (issue #49 sub-E)
- Ingest of the flat `.py` files in `/srv/streamlit/apps/` (e.g. `Francetv_magazine.py`, `MC360_Streamlit_BPM_v2.py`) — they have no clear "app boundary" to be a repo. Keep as-is for now.

## Decisions taken in brainstorming

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Repo owner | `gandalf` | Matches metablog ingest pattern (sub-B) |
| Repo name prefix | `streamlit-<appname>` | Mirrors `metablog-<site>` convention |
| Apps to ingest | All 30 **directory-form** entries in `/srv/streamlit/apps/` | Includes the 23 with `.git` and 7 without. Skip flat `.py` files and requirements |
| Source of truth post-ingest | Gitea | Local app dirs become deploy targets, refreshable from tags |
| Existing `.git/` (23 apps) | Retarget remote + push history (force-with-lease) | Preserves any local commits, no rewrite |
| Apps without `.git/` (7 apps) | `git init` + initial commit | Same as metablog B |
| Tag on initial state | `v1.0.0` on the HEAD commit after first push | Matches B |
| Deploy model | Clone from Gitea tag, backup current dir, replace in-place | Single active version; backup at `<app>.bak.<ts>` enables manual rollback |
| Multi-version layout | **Not adopted** | YAGNI; rollback is "restore from backup" instead |
| Auth | Same SSH key on `gandalf` Gitea account as B; no new tokens | Reuse the infrastructure built in B |
| Restart-after-deploy | If the app has a running instance, stop → swap → start | Avoids stale file handles |

## Architecture

### Component 1 — Streamlit app ingest (analogous to B)

Re-use the helpers from sub-project B as much as possible:

- `scripts/lib/gitea-ssh-preflight.sh` (no change)
- `scripts/lib/metablog-ingest-site.sh` is too domain-specific — write a sibling `scripts/lib/streamlit-ingest-app.sh` that does the same shape with different defaults (`GITEA_REPO_OWNER=gandalf`, repo prefix `streamlit-`).

Per-app function `ingest_streamlit_app <app_dir>`:

```
name = basename($app_dir)
repo_url = "ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-<name>.git"
status = (same flow as metablog-ingest-site.sh)
```

Orchestrator `scripts/streamlit-ingest.sh`:

- Pre-flights identical to B (SSH path, push-create probe, disk)
- Iterates over `find /srv/streamlit/apps -maxdepth 1 -mindepth 1 -type d`
- Same JSON report at `output/streamlit-ingest-report.json`

### Component 2 — Deploy with `--tag`

Extend the existing `packages/secubox-streamlit/scripts/streamlitctl` with:

```
streamlitctl deploy <app> --from-gitea --tag <vX.Y.Z>
streamlitctl deploy <app> --from-gitea --branch main          # latest
streamlitctl rollback <app>                                   # restore latest .bak.*
```

The deploy flow:

1. **Pre-check**: the Gitea repo `gandalf/streamlit-<app>` exists; the requested tag exists. If not, exit with a clear error.
2. **Backup**: if `/srv/streamlit/apps/<app>/` exists, rename it to `<app>.bak.<epoch>`. Keep at most the **3 most recent** backups (older ones auto-pruned).
3. **Clone**: `git clone --branch <tag> ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-<app>.git /srv/streamlit/apps/<app>` (uses the existing MOCHAbin SSH key enrolled in B).
4. **Permissions**: `chown -R 1000:1000 /srv/streamlit/apps/<app>` (the LXC's uid).
5. **Restart**: if `streamlitctl status <app>` reports running, `streamlitctl stop <app>` → `streamlitctl start <app>`. Otherwise leave stopped.
6. **Record**: write `/srv/streamlit/apps/<app>/.deploy.json` with `{tag, deployed_at, previous_backup}` for the API and rollback to consume.

### Component 3 — `current_tag` in the API

Modify `packages/secubox-streamlit/api/main.py`'s `_get_apps()` to enrich each app entry with:

```python
{
    "name": ...,
    "current_tag": _read_current_tag(app_dir),  # NEW
    "deployed_at": _read_deployed_at(app_dir),  # NEW
    ...existing fields
}
```

`_read_current_tag()` returns:

1. The `tag` field from `<app>/.deploy.json` if present (canonical source)
2. Otherwise the output of `git -C <app_dir> describe --tags --exact-match 2>/dev/null` (best-effort)
3. Otherwise `null`

`_read_deployed_at()` mirrors the same priority.

No change to the existing `/deploy`, `/start`, `/stop`, `/logs` endpoints — those continue to work as before. The new tag-based deploy is added as a **separate CLI flag** (`--from-gitea --tag <v>`), not a new endpoint, to keep API surface stable.

### Component 4 — Rollback

`streamlitctl rollback <app>`:

1. Find the latest `<app>.bak.*` directory under `/srv/streamlit/apps/`.
2. Move current `<app>/` to `<app>.bak.rolledback.<ts>` (don't lose it in case the rollback was wrong).
3. Rename the latest `.bak` to `<app>/`.
4. Re-record `.deploy.json` (tag becomes "rolled-back-from-`<previous_tag>`").
5. Restart if it was running.

Bounded: only the most recent backup is restorable via this command. Older ones live on disk for ~3 deploys' worth before auto-prune.

## Files

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `scripts/lib/streamlit-ingest-app.sh` | Per-app ingest function (sibling of `metablog-ingest-site.sh`) |
| Create | `scripts/streamlit-ingest.sh` | Orchestrator (preflights + loop + report) |
| Modify | `packages/secubox-streamlit/scripts/streamlitctl` | Add `--from-gitea --tag` to `deploy`; add `rollback` subcommand |
| Modify | `packages/secubox-streamlit/api/main.py` | `current_tag` + `deployed_at` in `/apps` and `/app/<name>` |
| Modify | `packages/secubox-streamlit/api/routers/<existing>.py` (whichever defines `/apps`) | Same as above |
| Create | `tests/scripts/test-streamlit-ingest.sh` | 3-app smoke test (mirror of B's smoke) |
| Create | `tests/scripts/test-streamlit-deploy-tag.sh` | Deploy `<app> --tag v1.0.0` end-to-end, verify file content + `.deploy.json` + API response |
| Modify | `.gitignore` | Ignore `output/streamlit-ingest-report.json` and log |
| Modify | `packages/secubox-streamlit/README.md` | Document the version-pin workflow |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 163 entry |

## Validation gate

1. `bash scripts/streamlit-ingest.sh` → 30 ok+skip, 0 fail. Report at `output/streamlit-ingest-report.json`.
2. `https://gitea.gk2.secubox.in/gandalf/?tab=repositories&q=streamlit` lists 30 `streamlit-*` repos.
3. Each has tag `v1.0.0` (cross-check 5 random ones via `git ls-remote --tags`).
4. `streamlitctl deploy yijing --from-gitea --tag v1.0.0` succeeds:
   - Backup `yijing.bak.<ts>` created.
   - `/srv/streamlit/apps/yijing/.deploy.json` exists with `tag = "v1.0.0"`.
   - Running yijing instance restarted (verify by `streamlitctl status yijing`).
5. `curl -s --unix-socket /run/secubox/streamlit.sock http://x/apps | jq '.[] | select(.name=="yijing").current_tag'` → `"v1.0.0"`.
6. `streamlitctl rollback yijing` → original content restored, `.deploy.json` records the rollback.

## Error handling

| Failure | Detection | Response |
|---------|-----------|----------|
| Gitea repo doesn't exist for an app | `git ls-remote` fails | `streamlitctl deploy` exits non-zero with `repo not found at gandalf/streamlit-<app>` |
| Requested tag doesn't exist | `git clone --branch <tag>` fails | Exit non-zero; current app dir untouched |
| Disk full mid-clone | Clone exits non-zero | Restore backup (don't leave a half-cloned dir) |
| Running instance refuses to stop | `streamlitctl stop` non-zero | Warn but proceed with swap; manual cleanup needed |
| `.deploy.json` write fails | Filesystem error | Warn; deploy succeeded but version is unknown to the API |

## Testing

Operational. Two smoke tests:

- `tests/scripts/test-streamlit-ingest.sh` — `--limit 3` ingest + idempotent re-run (mirrors B's pattern).
- `tests/scripts/test-streamlit-deploy-tag.sh` — full deploy/rollback cycle on one canary app.

No unit tests added.

## Open questions

None blocking.

## Licensing

CMSD-1.0. Bash scripts get the SPDX header per the license-headers tool (#81). Python changes inherit the existing module header.
