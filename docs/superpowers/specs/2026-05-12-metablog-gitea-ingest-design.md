<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer → Gitea Ingest — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#94](https://github.com/CyberMind-FR/secubox-deb/issues/94) (sub-project B of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#93](https://github.com/CyberMind-FR/secubox-deb/pull/93) (Gitea routing repair — already live on `gitea.gk2.secubox.in`)

## Context

166 static MetaBlogizer sites live under `/srv/metablogizer/sites/<name>/` on the MOCHAbin (267 MB total, ~1.6 MB/site median). The new Gitea at `gitea.gk2.secubox.in` is up but empty.

The terrain audit shows:

| Subset | Count | Existing state |
|--------|-------|----------------|
| Has local `.git/` pointing at the old `192.168.255.1:3001` Gitea | ~50 | 1-commit history, remote unreachable today |
| Has `.git/` pointing at `git.gk2.secubox.in/gandalf/droplet-sites/` | ~33 | Same shape, different remote |
| No `.git/` at all | ~83 | Raw files only |
| Has `site.json` metadata | 61 | Optional |

We need to publish all 166 into the new Gitea as `gandalf/metablog-<name>`, preserving the small local history when present, creating fresh history otherwise.

## Goal

Idempotent ingest pipeline that takes `/srv/metablogizer/sites/*` and ensures each site exists as a Gitea repo at `https://gitea.gk2.secubox.in/gandalf/metablog-<name>`, tagged `v1.0.0` on the initial commit, content pushed.

## Non-goals

- Modifying MetaBlogizer's nginx layout or site content
- Streamlit deployment (sub-project F, separate issue)
- Site.json schema evolution (sub-project C, separate)
- Multi-version workflow / rollback (sub-project D)
- Webhook deploy back to nginx (sub-project E)

## Decisions taken

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Repo owner | `gandalf` user (not an org) | Matches old `192.168.255.1:3001` naming, easy lookup if old Gitea ever resurrects |
| Repo name prefix | `metablog-<sitename>` | Matches old pattern verbatim. Also applies to the 12 sites whose old remote was `gandalf/droplet-sites/<X>` — they are unified into `gandalf/metablog-<X>` in the new Gitea (single namespace, simpler downstream tooling) |
| Existing `.git/` | Re-target remote + push history | Preserves the 1 commit each old site has, avoids unnecessary content rewrite |
| No `.git/` | `git init` + initial commit `feat: import from /srv/metablogizer/sites/<name>` | Fresh history, single commit |
| Auth for repo creation | Enable `ENABLE_PUSH_CREATE_USER=true` in Gitea app.ini, then push creates the repo automatically | Avoids API token plumbing; matches "SSH only" answer |
| Auth for push | SSH key on `gandalf` Gitea account | The MOCHAbin root's key gets enrolled once; subsequent pushes are passwordless |
| Default branch | `main` (Gitea default since 1.18) | Site `.git/` repos today are on `master` — `git push gitea master:main` renames during push |
| Tag on initial state | `v1.0.0` on the HEAD commit after first push | Per the issue text; future sub-projects (C/D) consume this |
| Failure handling | Skip + record in `output/ingest-report.json` (per-site `ok`/`failed`/`reason`), do NOT halt | 166 sites is a lot; one bad site shouldn't block the others |
| Re-run safety | If Gitea repo already exists AND HEAD commit matches local HEAD, skip | Idempotent across re-runs |

## Architecture

### Component 1 — Gitea config bootstrap

One-time change to the Gitea LXC's `app.ini`:

```ini
[repository]
ENABLE_PUSH_CREATE_USER = true
DEFAULT_BRANCH = main
```

Followed by `systemctl restart gitea` inside the LXC. Done by a script `scripts/metablog-ingest-gitea-config.sh` that:

1. Reads `app.ini` (likely `/etc/gitea/app.ini` inside the LXC).
2. Adds the keys if missing.
3. Restarts Gitea (only if changes were made).

Idempotent — re-running is a no-op once the keys are present.

### Component 2 — SSH key enrolment on `gandalf`

The push step needs a passwordless SSH path from MOCHAbin (where `/srv/metablogizer/sites/` lives) to `gitea.gk2.secubox.in:2222` (the public SSH frontend → 10.100.0.40:2222 inside the LXC).

Pre-flight check:

```bash
ssh -p 2222 -o BatchMode=yes git@gitea.gk2.secubox.in 2>&1 | head -1
```

- If it prints `Hi there, you've successfully authenticated, ... <gandalf>!` → we're done.
- If it prints `Permission denied (publickey)` → enroll the MOCHAbin's root `id_*.pub` into Gitea via:
  ```bash
  gitea-attach gandalf-keys-add /path/to/key.pub
  ```
  (helper that wraps `lxc-attach -n gitea -- su gitea -c "gitea admin user generate-access-token ..."` if needed, or simply writes to `gandalf`'s `~/.ssh/authorized_keys` directly via the LXC; details locked in the plan)

The ingest script refuses to start unless this preflight passes.

### Component 3 — Per-site ingest function

For a single site directory `$SITE_DIR`:

```
name = basename($SITE_DIR)                # e.g. "zkp"
repo_url = "ssh://git@gitea.gk2.secubox.in:2222/gandalf/metablog-$name.git"
remote_head = (try to fetch from Gitea; empty if repo doesn't exist yet)

if [ -d "$SITE_DIR/.git" ]:
    local_head = git -C "$SITE_DIR" rev-parse HEAD
    if remote_head == local_head:
        STATUS = "skip-already-ingested"
        return
    git -C "$SITE_DIR" remote set-url origin "$repo_url"
    git -C "$SITE_DIR" push origin HEAD:main --force-with-lease
    git -C "$SITE_DIR" tag -f v1.0.0
    git -C "$SITE_DIR" push origin v1.0.0
    STATUS = "ingest-with-history"

else:
    git -C "$SITE_DIR" init -b main
    git -C "$SITE_DIR" add .
    git -C "$SITE_DIR" commit -m "feat: import from /srv/metablogizer/sites/$name"
    git -C "$SITE_DIR" remote add origin "$repo_url"
    git -C "$SITE_DIR" push origin main
    git -C "$SITE_DIR" tag v1.0.0
    git -C "$SITE_DIR" push origin v1.0.0
    STATUS = "ingest-fresh"
```

All operations use `--quiet` flags except errors. The `--force-with-lease` on the push line is a safety net for the rare case where the remote got a different history (operator pushed something manually first); we never blow away unknown remote work.

### Component 4 — Orchestrator

`scripts/metablog-ingest.sh`:

```
1. Pre-flights:
   a. SSH preflight to gandalf@gitea.gk2.secubox.in:2222 (must succeed)
   b. Verify Gitea ENABLE_PUSH_CREATE_USER is true (curl /api/v1/version + a probe push to a /tmp test repo)
   c. Verify /srv/metablogizer/sites/ is non-empty and writable by us
   d. Disk-space check: pool needs at least 1 GB free on /data/volumes/gitea/repos/

2. Build site list:
   sites = ls /srv/metablogizer/sites/ | sort
   total = count(sites)

3. Loop:
   for each site in sites:
       run ingest-site(site)
       record result in REPORT[site] = {status, duration_ms, error}

4. Write report:
   output/ingest-report.json = { date, total, by_status: {ok: N, skip: M, fail: K}, sites: REPORT }

5. Print summary:
   "166 sites: 149 ingested, 12 skipped (already current), 5 failed (see output/ingest-report.json)"

Flags:
  --dry-run      print what would happen, no git operations
  --limit N      ingest only the first N sites (for staging runs)
  --site <name>  ingest only that one site
  --keep-going   continue past failures (default: yes)
  --halt-on-fail halt on first failure
```

### Component 5 — Smoke test on a 3-site subset

Before the full 166 run:

```bash
bash scripts/metablog-ingest.sh --limit 3
```

Validate:

1. 3 repos appear on `gitea.gk2.secubox.in/gandalf/?tab=repositories&q=metablog`
2. Each repo has at least 1 commit and tag `v1.0.0`
3. `git clone ssh://git@gitea.gk2.secubox.in:2222/gandalf/metablog-<name>.git /tmp/test-clone` works
4. The clone's `HEAD` SHA matches the source `/srv/metablogizer/sites/<name>/.git`'s HEAD (when applicable)
5. Re-running `--limit 3` results in 3 "skip-already-ingested" (idempotency)

### Component 6 — Full run + post-run verification

```bash
bash scripts/metablog-ingest.sh > output/ingest-full.log 2>&1
```

Verification gate:

1. `output/ingest-report.json` exists, `by_status.ok + by_status.skip` ≥ 160 (allow a handful of legitimate fails)
2. `curl -s -u gandalf:<token> https://gitea.gk2.secubox.in/api/v1/users/gandalf/repos?limit=50&q=metablog | jq length` ≥ 160
3. For 5 random sites, clone + diff against source `/srv/metablogizer/sites/<name>/` shows zero file changes (modulo `.git/` metadata)

If any of those fail: the report file enumerates per-site issues, fix individually with `--site <name>`.

## Files

| Action | Path | Purpose |
|--------|------|---------|
| Create | `scripts/metablog-ingest.sh` | Orchestrator (loops sites, calls helpers) |
| Create | `scripts/metablog-ingest-gitea-config.sh` | One-time `app.ini` patch for ENABLE_PUSH_CREATE_USER |
| Create | `scripts/lib/metablog-ingest-site.sh` | Per-site function (sourced by the orchestrator) |
| Create | `scripts/lib/gitea-ssh-preflight.sh` | SSH preflight + key enrol helper |
| Create | `tests/scripts/test-metablog-ingest.sh` | Dry-run smoke test |
| Create | `output/.gitkeep` | Keep `output/` in repo (for report files at runtime) |
| Modify | `.gitignore` | Ignore `output/ingest-report.json`, `output/ingest-full.log` |
| Modify | `packages/secubox-metablogizer/README.md` | Document the ingest CLI |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 162 entry |

## Error handling

| Failure mode | Detection | Response |
|--------------|-----------|----------|
| Gitea push-create not enabled | preflight push to `/tmp/test-repo` fails | Halt, instruct operator to run `metablog-ingest-gitea-config.sh` first |
| SSH key not enrolled on gandalf | preflight `ssh` returns publickey-denied | Halt, instruct operator to `gitea-ssh-preflight.sh --enroll` |
| Single site push fails (e.g., corrupt .git, disk full) | non-zero exit from push | Record in report, skip to next site (unless `--halt-on-fail`) |
| Repo already exists with non-matching history on Gitea | `--force-with-lease` rejects | Record in report as `conflict`, skip (operator decides) |
| Disk space exhausted mid-run | df check between sites | Halt, report ingested count so far |

## Testing

This is operational (writes to a production Gitea, modifies persistent state). Testing strategy:

1. **Dry-run mode** validates the orchestrator's flow without git operations.
2. **`--limit 3` staging run** validates a small subset end-to-end.
3. **Full run + verification gate** is the actual test.

No unit tests are added — the script is a thin wrapper around `git` and `ssh`.

## Rollback

If a full run goes sideways:

```bash
# Per-site: delete the Gitea repo via web UI (or API DELETE /api/v1/repos/gandalf/metablog-<name>)
# Local: rm -rf /srv/metablogizer/sites/<name>/.git  (if Component 3's git init was unwanted)
```

For a bulk rollback (rare):

```bash
# Delete all metablog-* repos on Gitea via API loop
# Restore /srv/metablogizer/sites/ from backup if file modifications were unintended (Component 3 only stages files in git, never modifies the working tree)
```

## Open questions

None blocking. The exact mechanism to enrol a Gitea SSH key without an API token is the only fuzzy spot; the plan resolves it concretely.

## Licensing

Per [`.claude/CLAUDE.md`](../../../.claude/CLAUDE.md), all first-party code ships under CMSD-1.0. Bash scripts get the standard CMSD-1.0 SPDX header per the license-headers tool (issue #81).
