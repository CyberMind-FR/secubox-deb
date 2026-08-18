<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Streamlit Gitea Version Pinning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mirror the 30 directory-form Streamlit apps from `/srv/streamlit/apps/` (on the MOCHAbin) into Gitea as `gandalf/streamlit-<app>` with `v1.0.0` tags, then extend `streamlitctl` with `--from-gitea --tag` deploy that clones a tag in-place with backup, restarts the running instance if any, and surfaces the active tag via the existing FastAPI.

**Architecture:** Reuse the per-site ingest pattern from sub-project B (#94 PR #97) — same SSH path, same `gitea@gitea.gk2.secubox.in:2222`, same idempotent retarget-or-init logic. Add three concerns: (1) deploy from Gitea tag with backup-and-replace; (2) `current_tag` / `deployed_at` enrichment in `/api/v1/streamlit/apps`; (3) rollback to latest backup.

**Tech Stack:** Bash 5 (strict mode), `git` over SSH, existing Python FastAPI (`packages/secubox-streamlit/api/main.py`), `streamlitctl` (bash CLI). No new daemons or systemd units.

**Spec:** [docs/superpowers/specs/2026-05-12-streamlit-gitea-version-pinning-design.md](../specs/2026-05-12-streamlit-gitea-version-pinning-design.md)
**Issue:** [#95](https://github.com/CyberMind-FR/secubox-deb/issues/95) (sub-project F of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** PR #97 patterns (`gandalf` SSH key already enrolled in Gitea, `ENABLE_PUSH_CREATE_USER=true`, `gitea@` SSH user).

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `scripts/lib/streamlit-ingest-app.sh` | Per-app ingest function (sibling of `metablog-ingest-site.sh`) |
| Create | `scripts/streamlit-ingest.sh` | Orchestrator: preflights → loop → JSON report |
| Modify | `packages/secubox-streamlit/scripts/streamlitctl` | Add `--from-gitea --tag` to deploy; add `rollback <app>` subcommand |
| Modify | `packages/secubox-streamlit/api/main.py` | Enrich `_get_apps()` with `current_tag` + `deployed_at` from `.deploy.json` |
| Create | `tests/scripts/test-streamlit-ingest.sh` | 3-app smoke + idempotent re-run |
| Create | `tests/scripts/test-streamlit-deploy-tag.sh` | Deploy/rollback cycle on one canary app |
| Modify | `.gitignore` | Ignore `output/streamlit-ingest-report.json`, log |
| Modify | `packages/secubox-streamlit/README.md` | Document the version-pin workflow |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 163 entry |
| Create | `docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md` | Record of the full run |

Reuse from PR #97 (already on master after that PR merges, otherwise we cherry-pick selectively when finishing the worktree):

- `scripts/lib/gitea-ssh-preflight.sh` — no change
- `scripts/lib/test-helpers.sh` — no change
- `scripts/metablog-ingest-gitea-config.sh` — no change (Gitea is already correctly configured)

---

## Task 1: Per-app ingest function

**Files:**
- Create: `scripts/lib/streamlit-ingest-app.sh`

This is the sibling of `scripts/lib/metablog-ingest-site.sh`. Same flow, different defaults (`GITEA_REPO_OWNER=gandalf` and the repo name prefix becomes `streamlit-`).

- [ ] **Step 1: Verify branch**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/95-streamlit-per-site-version-pinning-conta
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/95-streamlit-per-site-version-pinning-conta`. Otherwise BLOCKED.

- [ ] **Step 2: Create `scripts/lib/streamlit-ingest-app.sh`**

```bash
#!/usr/bin/env bash
# scripts/lib/streamlit-ingest-app.sh
# Per-app ingest function for Streamlit apps. Sourceable.
#
# Provides: ingest_streamlit_app <app_dir>
#   - prints one status keyword on stdout:
#       ingested-fresh         : app had no .git, fresh init + push + tag
#       ingested-with-history  : app had .git, retargeted + pushed + tag
#       skip-already-current   : remote HEAD == local HEAD, idempotent skip
#       fail-<reason>          : something went wrong
#   - returns 0 on any "ingested-*" or "skip-*", non-zero on "fail-*"
#
# Mirrors scripts/lib/metablog-ingest-site.sh with two differences:
#   - Repo name prefix is "streamlit-" instead of "metablog-"
#   - LXC bind mount is /srv/streamlit/apps (vs /srv/metablogizer/sites)
#
# Important: Gitea SSH user is "gitea" (NOT "git").

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
GITEA_REPO_OWNER="${GITEA_REPO_OWNER:-gandalf}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

_streamlit_git_ssh_cmd() {
  echo "ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
}

ingest_streamlit_app() {
  local app_dir="$1"
  [[ -z "$app_dir" ]] && { echo "fail-no-arg"; return 1; }

  local name repo_url
  name=$(basename "$app_dir")
  repo_url="ssh://${GITEA_SSH_USER}@${GITEA_HOST}:${GITEA_SSH_PORT}/${GITEA_REPO_OWNER}/streamlit-${name}.git"

  ssh "root@$LXC_HOST" bash <<EOSH
set -euo pipefail
APP="$app_dir"
NAME="$name"
REPO_URL="$repo_url"
GIT_SSH_COMMAND="$(_streamlit_git_ssh_cmd)"
export GIT_SSH_COMMAND

if [[ ! -d "\$APP" ]]; then
  echo "fail-no-such-dir"
  exit 1
fi

# Permit git in dirs we don't own (LXC apps live as uid 1000)
git config --global --add safe.directory "\$APP" 2>/dev/null || true

cd "\$APP"

remote_head=\$(git ls-remote "\$REPO_URL" main 2>/dev/null | awk '{print \$1}' || true)

if [[ -d .git ]]; then
  local_head=\$(git rev-parse --verify HEAD 2>/dev/null || true)
  if [[ -n "\$remote_head" && "\$remote_head" == "\$local_head" ]]; then
    echo "skip-already-current"
    exit 0
  fi

  if [[ -z "\$local_head" ]]; then
    # .git exists but no commits (unborn branch). Treat as fresh.
    git symbolic-ref HEAD refs/heads/main 2>/dev/null || true
    git add -A
    if git diff --cached --quiet; then
      echo "fail-empty-dir"
      exit 1
    fi
    git -c user.email=streamlit-ingest@cybermind.fr -c user.name="Streamlit Ingest" \\
        commit -q -m "feat: import from /srv/streamlit/apps/\$NAME"
    git remote add origin "\$REPO_URL" 2>/dev/null \\
      || git remote set-url origin "\$REPO_URL"
    git push --quiet origin main
    git tag v1.0.0
    git push --quiet origin v1.0.0
    echo "ingested-fresh"
    exit 0
  fi

  git remote set-url origin "\$REPO_URL" 2>/dev/null \\
    || git remote add origin "\$REPO_URL"
  src_branch=\$(git symbolic-ref --short HEAD 2>/dev/null || echo HEAD)
  if [[ -n "\$remote_head" ]]; then
    git push --quiet --force-with-lease origin "\$src_branch:main"
  else
    git push --quiet --force origin "\$src_branch:main"
  fi
  git tag -f v1.0.0
  git push --quiet --force origin v1.0.0
  echo "ingested-with-history"
  exit 0
else
  git init -q -b main
  git config user.email "streamlit-ingest@cybermind.fr"
  git config user.name "Streamlit Ingest"
  git add -A
  if git diff --cached --quiet; then
    echo "fail-empty-dir"
    exit 1
  fi
  git commit -q -m "feat: import from /srv/streamlit/apps/\$NAME"
  git remote add origin "\$REPO_URL"
  git push --quiet origin main
  git tag v1.0.0
  git push --quiet origin v1.0.0
  echo "ingested-fresh"
  exit 0
fi
EOSH
}
```

- [ ] **Step 3: Smoke-test on one app**

Pick an app that has `.git/` from the audit:

```bash
chmod +x scripts/lib/streamlit-ingest-app.sh
source scripts/lib/streamlit-ingest-app.sh
ingest_streamlit_app /srv/streamlit/apps/yijing 2>&1
```

Expected: `ingested-with-history` (first run) or `skip-already-current` (re-run).

- [ ] **Step 4: Idempotency check — same app again**

```bash
ingest_streamlit_app /srv/streamlit/apps/yijing 2>&1
```

Expected: `skip-already-current`.

- [ ] **Step 5: Verify on Gitea via SSH `ls-remote`**

```bash
ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes' git ls-remote ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-yijing.git" 2>&1 | head -5
```

Expected: two lines (`refs/heads/main` + `refs/tags/v1.0.0`), each with a 40-char SHA.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/streamlit-ingest-app.sh
git commit -m "feat(streamlit): Per-app ingest function (idempotent, history-preserving) (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Orchestrator

**Files:**
- Create: `scripts/streamlit-ingest.sh`

Same shape as `scripts/metablog-ingest.sh` from PR #97 but iterates over `/srv/streamlit/apps/` (directories only) and uses `ingest_streamlit_app`.

- [ ] **Step 1: Verify branch.**

- [ ] **Step 2: Determine whether `scripts/lib/gitea-ssh-preflight.sh` exists in this branch.**

```bash
test -f scripts/lib/gitea-ssh-preflight.sh && echo "preflight available" || echo "NOT available — copy from feature/94 branch"
```

If `preflight available`, proceed. Otherwise the branch needs to pick up the helper from PR #97 — either cherry-pick its commit `06d35317` (or the merge SHA once #97 is merged), or copy the file content verbatim. Document whichever path is taken in the commit message.

- [ ] **Step 3: Create `scripts/streamlit-ingest.sh`**

```bash
#!/usr/bin/env bash
# scripts/streamlit-ingest.sh
# Idempotent ingest of /srv/streamlit/apps/* (directories only) into
# gitea.gk2.secubox.in as gandalf/streamlit-<app>. Records per-app
# outcome in output/streamlit-ingest-report.json.
#
# Usage:
#   bash scripts/streamlit-ingest.sh [--dry-run] [--limit N] [--app <name>] [--halt-on-fail]
#
# Pre-flights (identical to the metablog ingest):
#   1. SSH preflight to gitea@gitea.gk2.secubox.in:2222 (from MOCHAbin)
#   2. Gitea ENABLE_PUSH_CREATE_USER is true (probed via test push)
#   3. /srv/streamlit/apps/ exists and has directory entries
#   4. /data/volumes/gitea/repos/ has >=1 GB free

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
# shellcheck source=lib/gitea-ssh-preflight.sh
source "$REPO/scripts/lib/gitea-ssh-preflight.sh"
# shellcheck source=lib/streamlit-ingest-app.sh
source "$REPO/scripts/lib/streamlit-ingest-app.sh"

LXC_HOST="${LXC_HOST:-192.168.1.200}"
APPS_DIR="${APPS_DIR:-/srv/streamlit/apps}"
DRY_RUN=0
LIMIT=0
ONLY_APP=""
HALT_ON_FAIL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)      DRY_RUN=1; shift ;;
    --limit)        LIMIT="$2"; shift 2 ;;
    --app)          ONLY_APP="$2"; shift 2 ;;
    --halt-on-fail) HALT_ON_FAIL=1; shift ;;
    *)              echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

REPORT="$REPO/output/streamlit-ingest-report.json"
LOG="$REPO/output/streamlit-ingest.log"
mkdir -p "$REPO/output"
: > "$LOG"

log() { printf '[streamlit-ingest] %s\n' "$*" | tee -a "$LOG" >&2; }
fail_pre() { log "PRE-FLIGHT FAIL: $*"; exit 1; }

# Save + clear positional args before sourcing (preflight helper checks $1)
saved_args=( "$@" )
set --
log "Pre-flight 1: SSH path"
ssh_preflight >>"$LOG" 2>&1 || fail_pre "SSH preflight failed (run scripts/lib/gitea-ssh-preflight.sh --enrol if needed)"
set -- "${saved_args[@]}"

log "Pre-flight 2: push-create probe"
probe_out=$(ssh "root@$LXC_HOST" "$(cat <<'EOPROBE'
tmp=$(mktemp -d)
cd "$tmp"
git init -q -b main
git config user.email probe@streamlit-ingest
git config user.name probe
echo probe > x.txt
git add x.txt
git commit -q -m probe
ts=$(date +%s)
GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
  git push --quiet "ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-preflight-probe-$ts.git" main 2>&1
rm -rf "$tmp"
EOPROBE
)" 2>&1 || true)
if echo "$probe_out" | grep -qE "fatal|denied|refused"; then
  fail_pre "Push-create probe failed: $(echo "$probe_out" | tail -1)"
fi

log "Pre-flight 3: apps dir + disk"
ssh "root@$LXC_HOST" "test -d $APPS_DIR && [ \$(find $APPS_DIR -maxdepth 1 -mindepth 1 -type d | wc -l) -gt 0 ]" \
  || fail_pre "$APPS_DIR has no directory entries"
free_kb=$(ssh "root@$LXC_HOST" "df --output=avail /data/volumes/gitea/repos 2>/dev/null | tail -1" || echo 0)
[[ "$free_kb" -gt 1048576 ]] \
  || fail_pre "Less than 1 GB free on /data/volumes/gitea/repos/ (got: ${free_kb}KB)"

log "Pre-flights OK"

# ───── App list ─────
if [[ -n "$ONLY_APP" ]]; then
  apps=("$ONLY_APP")
else
  mapfile -t apps < <(ssh "root@$LXC_HOST" "find $APPS_DIR -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | sort")
fi
[[ "$LIMIT" -gt 0 ]] && apps=("${apps[@]:0:$LIMIT}")
total=${#apps[@]}
log "Will process $total apps"

# ───── Loop ─────
declare -A RESULT
declare -A DURATION

count_ok=0
count_skip=0
count_fail=0
i=0
for a in "${apps[@]}"; do
  i=$((i+1))
  log "[$i/$total] $a"
  start=$(date +%s)
  if [[ $DRY_RUN -eq 1 ]]; then
    RESULT[$a]="dry-run"
    DURATION[$a]=0
    log "  DRY-RUN — would ingest"
    continue
  fi
  status=$(ingest_streamlit_app "$APPS_DIR/$a" 2>>"$LOG" | tail -1 | tr -d '\n' || echo "fail-internal-error")
  [[ -z "$status" ]] && status="fail-internal-error"
  end=$(date +%s)
  RESULT[$a]="$status"
  DURATION[$a]=$((end - start))
  log "  → $status (${DURATION[$a]}s)"

  case "$status" in
    ingested-*)  count_ok=$((count_ok+1)) ;;
    skip-*)      count_skip=$((count_skip+1)) ;;
    *)           count_fail=$((count_fail+1))
                 [[ $HALT_ON_FAIL -eq 1 ]] && { log "HALT-ON-FAIL: stopping at $a"; break; }
                 ;;
  esac
done

# ───── Report ─────
log "Writing $REPORT"
{
  echo "{"
  echo "  \"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"total\": $total,"
  echo "  \"by_status\": { \"ok\": $count_ok, \"skip\": $count_skip, \"fail\": $count_fail },"
  echo "  \"apps\": {"
  first=1
  for a in "${apps[@]}"; do
    [[ $first -eq 1 ]] && first=0 || echo ","
    echo -n "    \"$a\": { \"status\": \"${RESULT[$a]:-not-run}\", \"duration_s\": ${DURATION[$a]:-0} }"
  done
  echo ""
  echo "  }"
  echo "}"
} > "$REPORT"

log "Summary: $total total, $count_ok ingested, $count_skip skipped, $count_fail failed"
log "Report: $REPORT"
log "Log: $LOG"

[[ $count_fail -gt 0 ]] && exit 3 || exit 0
```

Note the **defensive `| tail -1 | tr -d '\n'`** on the status capture (PR #97's FU4 followup) so multi-line output from `ingest_streamlit_app` doesn't corrupt the JSON.

- [ ] **Step 4: Dry-run smoke**

```bash
chmod +x scripts/streamlit-ingest.sh
bash scripts/streamlit-ingest.sh --dry-run --limit 3 2>&1 | tail -10
```

Expected: 3 lines `[i/3] <appname> ... → dry-run`, summary `0 ingested, 0 skipped, 0 failed`.

- [ ] **Step 5: Report shape check**

```bash
jq . output/streamlit-ingest-report.json | head -20
```

Expected: valid JSON with `total: 3`, three app entries with `status: "dry-run"`.

- [ ] **Step 6: Commit**

```bash
git add scripts/streamlit-ingest.sh
git commit -m "feat(streamlit): Orchestrator for Gitea ingest (preflights + report) (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Smoke test — 3-app + idempotent re-run

**Files:**
- Create: `tests/scripts/test-streamlit-ingest.sh`

- [ ] **Step 1: Verify branch.**

- [ ] **Step 2: Write the smoke test**

```bash
#!/usr/bin/env bash
# tests/scripts/test-streamlit-ingest.sh
# Smoke test for the Streamlit → Gitea ingest pipeline.
# Runs against the live Gitea — NOT a unit test.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
REPORT="$REPO/output/streamlit-ingest-report.json"

log_step() { echo "[smoke step $1] $2"; }

# Step 1: Dry-run, --limit 3
log_step 1 "dry-run --limit 3"
bash "$REPO/scripts/streamlit-ingest.sh" --dry-run --limit 3 >/dev/null 2>&1
total=$(jq '.total' "$REPORT")
assert_eq "3" "$total" "dry-run total"

# Step 2: Real run, --limit 3
log_step 2 "live --limit 3"
bash "$REPO/scripts/streamlit-ingest.sh" --limit 3 >/dev/null 2>&1 || {
  echo "FAIL: live run errored. See $REPO/output/streamlit-ingest.log"
  tail -20 "$REPO/output/streamlit-ingest.log"
  exit 1
}
ok=$(jq '.by_status.ok + .by_status.skip' "$REPORT")
if [[ "$ok" -lt 3 ]]; then
  echo "FAIL: expected >=3 ok+skip, got $ok"
  jq . "$REPORT"
  exit 1
fi
pass "live --limit 3 produced $ok ok+skip apps"

# Step 3: Re-run — idempotent (all should skip)
log_step 3 "idempotent re-run"
bash "$REPO/scripts/streamlit-ingest.sh" --limit 3 >/dev/null 2>&1
skip=$(jq '.by_status.skip' "$REPORT")
assert_eq "3" "$skip" "all 3 should skip-already-current on re-run"

# Step 4: Verify on Gitea side via SSH (no public API call — uses ssh ls-remote)
log_step 4 "git ls-remote round-trip"
first_app=$(jq -r '.apps | to_entries[0].key' "$REPORT")
remote_head=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
  git ls-remote ssh://$GITEA_SSH_USER@$GITEA_HOST:$GITEA_SSH_PORT/gandalf/streamlit-$first_app.git main 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$remote_head" ]] || { echo "FAIL: ls-remote returned no HEAD for $first_app"; exit 1; }
pass "remote HEAD for $first_app is $remote_head"

# Step 5: Verify tag v1.0.0 exists
log_step 5 "tag v1.0.0 exists"
tag_sha=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p $GITEA_SSH_PORT -o BatchMode=yes' \
  git ls-remote --tags ssh://$GITEA_SSH_USER@$GITEA_HOST:$GITEA_SSH_PORT/gandalf/streamlit-$first_app.git v1.0.0 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$tag_sha" ]] || { echo "FAIL: v1.0.0 tag not found for $first_app"; exit 1; }
pass "tag v1.0.0 for $first_app is $tag_sha"

pass "all smoke checks passed"
```

- [ ] **Step 3: Run**

```bash
chmod +x tests/scripts/test-streamlit-ingest.sh
bash tests/scripts/test-streamlit-ingest.sh 2>&1 | tail -15
```

Expected: ends with `PASS: all smoke checks passed`. Steps 1-5 all show output.

If Step 5 fails, the tag wasn't pushed — investigate `ingest_streamlit_app` Step 6 in Task 1.

- [ ] **Step 4: Commit**

```bash
git add tests/scripts/test-streamlit-ingest.sh
git commit -m "test(streamlit): 3-app smoke for Gitea ingest (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Full ingest run on 30 apps

**Files:** none modified — verification + summary doc.

- [ ] **Step 1: Full run**

```bash
bash scripts/streamlit-ingest.sh 2>&1 | tail -10
```

Expected runtime: 3–10 minutes (similar density to B's 166-site run).

- [ ] **Step 2: Inspect report**

```bash
jq '.by_status' output/streamlit-ingest-report.json
jq -r '.apps | to_entries | map(select(.value.status | startswith("fail"))) | .[] | "\(.key): \(.value.status)"' output/streamlit-ingest-report.json
```

Expected: `ok + skip ≥ 28` (allow 2 legitimate fails). The second query lists per-app failures.

If the failure pattern matches PR #97's "pre-existing broken stub" symptom (`fatal: ... does not appear to be a git repository`), apply the same cleanup: generate a one-shot admin token, DELETE the broken repos, re-run. This is the same recipe from PR #97 commit `6ac39a6f`.

- [ ] **Step 3: Cross-check 5 random apps**

```bash
for app in $(jq -r '.apps | keys[]' output/streamlit-ingest-report.json | shuf | head -5); do
  head=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes' git ls-remote ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-$app.git main 2>/dev/null | awk '{print \$1}'")
  echo "$app: $head"
done
```

Expected: 5 lines, each with a 40-char SHA.

- [ ] **Step 4: Write run summary**

```bash
mkdir -p docs/superpowers/runs
{
  echo "# Streamlit Gitea Ingest Run — 2026-05-12"
  echo ""
  echo "Live run of \`scripts/streamlit-ingest.sh\` on the MOCHAbin."
  echo ""
  echo '```json'
  jq '.by_status' output/streamlit-ingest-report.json
  echo '```'
  echo ""
  echo "Per-app failures (if any):"
  echo ""
  echo '```'
  jq -r '.apps | to_entries | map(select(.value.status | startswith("fail"))) | .[] | "\(.key): \(.value.status)"' output/streamlit-ingest-report.json
  echo '```'
  echo ""
  echo "Verification (5 random apps, \`git ls-remote\`):"
  echo ""
  echo '```'
  for app in $(jq -r '.apps | keys[]' output/streamlit-ingest-report.json | shuf | head -5); do
    head=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes' git ls-remote ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-$app.git main 2>/dev/null | awk '{print \$1}'")
    echo "$app: $head"
  done
  echo '```'
} > docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md
```

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md
git commit -m "docs(streamlit): Full-run ingest summary (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: streamlitctl — add `--from-gitea --tag` to deploy + `rollback` subcommand

**Files:**
- Modify: `packages/secubox-streamlit/scripts/streamlitctl`

The existing `streamlitctl` has a `deploy` command. Add a flag-driven Gitea path. Add a new `rollback` top-level subcommand.

- [ ] **Step 1: Inspect the current deploy command structure**

```bash
grep -nE "^cmd_|deploy|rollback" packages/secubox-streamlit/scripts/streamlitctl | head -20
```

Note where `cmd_deploy` (or equivalent) lives. The plan assumes it accepts positional args today (app name + source); we will add long flags `--from-gitea` and `--tag`.

- [ ] **Step 2: Add the deploy flag-parsing + Gitea path**

In the function that handles `deploy` (likely `cmd_deploy()`), prepend flag parsing:

```bash
cmd_deploy() {
    local from_gitea=0
    local tag=""
    local branch="main"
    local args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --from-gitea)  from_gitea=1; shift ;;
            --tag)         tag="$2"; shift 2 ;;
            --branch)      branch="$2"; shift 2 ;;
            -h|--help)     echo "Usage: streamlitctl deploy <app> [--from-gitea --tag <vX.Y.Z> | --branch <name>]"; return 0 ;;
            *)             args+=("$1"); shift ;;
        esac
    done

    local app="${args[0]:-}"
    [[ -z "$app" ]] && { error "Usage: streamlitctl deploy <app> [--from-gitea --tag <vX.Y.Z>]"; return 1; }

    if [[ $from_gitea -eq 1 ]]; then
        deploy_from_gitea "$app" "$tag" "$branch"
        return $?
    fi

    # ... existing non-Gitea deploy logic continues below (unchanged) ...
}

deploy_from_gitea() {
    local app="$1" tag="$2" branch="$3"
    local repo_url="ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-${app}.git"
    local ref="${tag:-$branch}"
    local app_dir="${APPS_PATH}/${app}"
    local backup_dir="${APPS_PATH}/${app}.bak.$(date +%s)"

    require_root

    log "Deploying ${app} from Gitea (ref: ${ref})"

    # 1. Pre-check: repo + ref exist
    GIT_SSH_COMMAND="ssh -p 2222 -o BatchMode=yes" \
        git ls-remote "$repo_url" "$ref" 2>/dev/null | grep -q . \
        || { error "Ref '${ref}' not found at ${repo_url}"; return 1; }

    # 2. Backup current
    if [[ -d "$app_dir" ]]; then
        mv "$app_dir" "$backup_dir"
        log "Backup: $backup_dir"
    fi

    # 3. Clone
    if ! GIT_SSH_COMMAND="ssh -p 2222 -o BatchMode=yes" \
         git clone --quiet --branch "$ref" "$repo_url" "$app_dir"; then
        error "git clone failed; restoring backup"
        [[ -d "$backup_dir" ]] && mv "$backup_dir" "$app_dir"
        return 1
    fi

    # 4. Perms (LXC uid 1000)
    chown -R 1000:1000 "$app_dir"

    # 5. Record .deploy.json
    cat > "$app_dir/.deploy.json" <<EOJ
{
  "app": "${app}",
  "tag": "${tag:-}",
  "branch": "${tag:+}${tag:-${branch}}",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "previous_backup": "$(basename "$backup_dir")",
  "source_repo": "${repo_url}"
}
EOJ
    chown 1000:1000 "$app_dir/.deploy.json"

    # 6. Restart if was running
    local was_running=0
    if [[ -d "$backup_dir" ]]; then
        # Check via existing status mechanism — if the app had a running pid
        if cmd_status "$app" 2>/dev/null | grep -qi "running"; then
            was_running=1
        fi
    fi
    if [[ $was_running -eq 1 ]]; then
        log "Restarting ${app}"
        cmd_stop "$app" || warn "stop returned non-zero"
        cmd_start "$app" || warn "start returned non-zero"
    fi

    # 7. Prune old backups, keep 3 most recent
    local backups
    mapfile -t backups < <(ls -1dt "${APPS_PATH}/${app}.bak."* 2>/dev/null)
    if [[ ${#backups[@]} -gt 3 ]]; then
        for stale in "${backups[@]:3}"; do
            log "Pruning stale backup: $stale"
            rm -rf "$stale"
        done
    fi

    log "Deploy OK: ${app} @ ${ref}"
    return 0
}

cmd_rollback() {
    require_root
    local app="${1:-}"
    [[ -z "$app" ]] && { error "Usage: streamlitctl rollback <app>"; return 1; }

    local app_dir="${APPS_PATH}/${app}"
    local latest_backup
    latest_backup=$(ls -1dt "${APPS_PATH}/${app}.bak."* 2>/dev/null | head -1)
    [[ -z "$latest_backup" ]] && { error "No backup found for ${app}"; return 1; }

    log "Rolling ${app} back to $(basename "$latest_backup")"

    # Move current aside (don't lose it)
    if [[ -d "$app_dir" ]]; then
        mv "$app_dir" "${app_dir}.bak.rolledback.$(date +%s)"
    fi
    mv "$latest_backup" "$app_dir"
    chown -R 1000:1000 "$app_dir"

    # Record the rollback in .deploy.json (best-effort)
    if [[ -f "$app_dir/.deploy.json" ]]; then
        local prev_tag
        prev_tag=$(grep '"tag"' "$app_dir/.deploy.json" 2>/dev/null | sed -E 's/.*"tag": *"([^"]*)".*/\1/')
        cat > "$app_dir/.deploy.json" <<EOJ
{
  "app": "${app}",
  "tag": "${prev_tag}",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rolled_back_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOJ
        chown 1000:1000 "$app_dir/.deploy.json"
    fi

    # Restart if was running
    if cmd_status "$app" 2>/dev/null | grep -qi "running"; then
        cmd_stop "$app" || true
        cmd_start "$app" || true
    fi

    log "Rollback OK: ${app}"
    return 0
}
```

Add the `rollback)` arm in the main command dispatcher (search for `case "$cmd" in` or the equivalent and add a line):

```bash
        rollback)
            cmd_rollback "$@"
            ;;
```

- [ ] **Step 3: Shell-syntax-check**

```bash
bash -n packages/secubox-streamlit/scripts/streamlitctl && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 4: Make sure the deploy help still works**

```bash
bash packages/secubox-streamlit/scripts/streamlitctl deploy --help 2>&1 | head -5
```

Expected: usage line including `--from-gitea --tag`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-streamlit/scripts/streamlitctl
git commit -m "feat(streamlit): deploy --from-gitea --tag + rollback subcommand (ref #95)

deploy_from_gitea:
- pre-check repo + ref exist (git ls-remote)
- backup current app dir to <app>.bak.<ts>
- git clone --branch <tag> into /srv/streamlit/apps/<app>/
- chown 1000:1000 for LXC
- write .deploy.json with tag + deployed_at + previous_backup
- restart running instance if any
- prune backups beyond the 3 most recent

cmd_rollback:
- find latest <app>.bak.*
- move current aside as <app>.bak.rolledback.<ts>
- promote backup to current
- restart if was running

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: API — `current_tag` + `deployed_at` in `_get_apps()`

**Files:**
- Modify: `packages/secubox-streamlit/api/main.py`

The current `_get_apps()` just calls `streamlitctl app list` and returns its JSON. To surface the tag, enrich each entry by reading `<APPS_PATH>/<app>/.deploy.json`.

- [ ] **Step 1: Find the current implementation**

```bash
grep -nA5 "^def _get_apps" packages/secubox-streamlit/api/main.py
```

Note the file structure around it.

- [ ] **Step 2: Add the enrichment helpers + modify `_get_apps`**

Replace the existing `_get_apps()` function (lines 151-154) with:

```python
APPS_PATH = "/srv/streamlit/apps"


def _read_deploy_metadata(app_name: str) -> dict:
    """Read .deploy.json for an app; return empty dict if absent or invalid."""
    path = Path(APPS_PATH) / app_name / ".deploy.json"
    try:
        with path.open() as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return {}


def _git_describe_tag(app_name: str) -> str | None:
    """Fallback: read the current tag via `git describe --tags --exact-match`."""
    app_dir = Path(APPS_PATH) / app_name
    if not (app_dir / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(app_dir), "describe", "--tags", "--exact-match"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_apps() -> List[dict]:
    """Get list of apps from streamlitctl, enriched with current_tag + deployed_at."""
    result = _run_ctl("app", "list")
    apps = result.get("apps", [])
    for app in apps:
        name = app.get("name")
        if not name:
            continue
        meta = _read_deploy_metadata(name)
        app["current_tag"] = meta.get("tag") or _git_describe_tag(name)
        app["deployed_at"] = meta.get("deployed_at")
    return apps
```

(`APPS_PATH` constant declaration goes at module level near the other constants. If `Path` is not already imported, the existing line `from pathlib import Path` should already be there per the file head — verify and add if missing.)

- [ ] **Step 3: Syntax check**

```bash
python3 -c "import ast; ast.parse(open('packages/secubox-streamlit/api/main.py').read())" && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 4: Verify the `_get_apps()` flow**

If pytest is set up for this package, run any existing tests:

```bash
find packages/secubox-streamlit -name "*test*.py" 2>&1 | head -5
```

If there are existing API tests, run them: `pytest packages/secubox-streamlit/`.

Either way, verify by sourcing the module in a Python shell:

```bash
cd packages/secubox-streamlit && python3 -c "
import sys
sys.path.insert(0, 'api')
import main
# Verify the helpers exist
assert hasattr(main, '_read_deploy_metadata')
assert hasattr(main, '_git_describe_tag')
print('helpers present')
"
```

Expected: `helpers present`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-streamlit/api/main.py
git commit -m "feat(streamlit-api): current_tag + deployed_at in /apps (ref #95)

_get_apps() now enriches each app with:
- current_tag: from <app>/.deploy.json if present, fallback to
  git describe --tags --exact-match
- deployed_at: from <app>/.deploy.json

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Deploy/rollback cycle smoke test

**Files:**
- Create: `tests/scripts/test-streamlit-deploy-tag.sh`

This is a live test — picks one canary app (`yijing`, which we know has `.git` and was ingested in Task 4), deploys at v1.0.0, verifies `.deploy.json` and API reflect the tag, then rolls back.

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
# tests/scripts/test-streamlit-deploy-tag.sh
# End-to-end smoke for streamlitctl deploy --from-gitea --tag + rollback.
# Canary: yijing (known to have .git and be in Gitea after Task 4).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

CANARY="${CANARY:-yijing}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

log_step() { echo "[deploy-test step $1] $2"; }

# Step 1: Confirm canary exists on Gitea at v1.0.0
log_step 1 "canary exists in Gitea at v1.0.0"
tag_sha=$(ssh "root@$LXC_HOST" "GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes' \
  git ls-remote --tags ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-$CANARY.git v1.0.0 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$tag_sha" ]] || { echo "FAIL: canary $CANARY has no v1.0.0 tag on Gitea"; exit 1; }
pass "v1.0.0 sha: $tag_sha"

# Step 2: Capture pre-state (was the app running?)
log_step 2 "pre-state"
was_running=$(ssh "root@$LXC_HOST" "/usr/local/sbin/streamlitctl status $CANARY 2>/dev/null | grep -qi running && echo yes || echo no")
echo "  was_running=$was_running"

# Step 3: Deploy --from-gitea --tag v1.0.0
log_step 3 "deploy --from-gitea --tag v1.0.0"
ssh "root@$LXC_HOST" "/usr/local/sbin/streamlitctl deploy $CANARY --from-gitea --tag v1.0.0" 2>&1 | tail -3

# Step 4: Verify .deploy.json
log_step 4 ".deploy.json present + correct tag"
tag_in_json=$(ssh "root@$LXC_HOST" "cat /srv/streamlit/apps/$CANARY/.deploy.json 2>/dev/null | grep -oE '\"tag\": *\"[^\"]*\"' | head -1 | sed 's/.*\"tag\": *\"\\([^\"]*\\)\".*/\\1/'")
assert_eq "v1.0.0" "$tag_in_json" ".deploy.json tag"

# Step 5: Verify API surfaces current_tag
log_step 5 "API current_tag == v1.0.0"
api_tag=$(curl -s --unix-socket /run/secubox/streamlit.sock http://x/apps 2>/dev/null \
  | jq -r --arg n "$CANARY" '.apps[] | select(.name==$n) | .current_tag')
if [[ "$api_tag" != "v1.0.0" ]]; then
  echo "FAIL: API current_tag for $CANARY is '$api_tag', expected 'v1.0.0'"
  exit 1
fi
pass "API current_tag for $CANARY is v1.0.0"

# Step 6: Backup directory exists
log_step 6 "backup directory exists"
backup_count=$(ssh "root@$LXC_HOST" "ls -d /srv/streamlit/apps/$CANARY.bak.* 2>/dev/null | wc -l")
[[ "$backup_count" -ge 1 ]] || { echo "FAIL: no backup dir for $CANARY"; exit 1; }
pass "$backup_count backup(s) present"

# Step 7: Rollback
log_step 7 "rollback"
ssh "root@$LXC_HOST" "/usr/local/sbin/streamlitctl rollback $CANARY" 2>&1 | tail -3
# After rollback, the latest .bak.* should have become the current dir.
# A rolled-back-from sentinel backup should exist.
sentinel_count=$(ssh "root@$LXC_HOST" "ls -d /srv/streamlit/apps/$CANARY.bak.rolledback.* 2>/dev/null | wc -l")
[[ "$sentinel_count" -ge 1 ]] || { echo "FAIL: no rolledback sentinel for $CANARY"; exit 1; }
pass "rollback produced rolledback sentinel"

pass "all deploy/rollback checks passed"
```

- [ ] **Step 2: Run**

```bash
chmod +x tests/scripts/test-streamlit-deploy-tag.sh
bash tests/scripts/test-streamlit-deploy-tag.sh 2>&1 | tail -15
```

Expected: ends with `PASS: all deploy/rollback checks passed`. 7 step lines visible.

If Step 5 fails: the API hasn't refreshed yet — verify the FastAPI is reachable on the Unix socket. The `_get_apps()` cache might have stale data; the API has an internal refresh loop (see `_cache_refresh_loop` in `api/main.py`). Either wait 30s and retry, or restart the API service inside the LXC.

- [ ] **Step 3: Commit**

```bash
git add tests/scripts/test-streamlit-deploy-tag.sh
git commit -m "test(streamlit): Deploy/rollback cycle smoke (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: .gitignore + README + WIP/HISTORY tracking

**Files:**
- Modify: `.gitignore`
- Modify: `packages/secubox-streamlit/README.md`
- Modify: `.claude/WIP.md`, `.claude/HISTORY.md`

- [ ] **Step 1: Append to `.gitignore`**

```bash
cat >> .gitignore <<'EOF'

# Streamlit ingest artifacts (regenerated each run)
/output/streamlit-ingest-report.json
/output/streamlit-ingest.log
EOF
```

- [ ] **Step 2: Append to `packages/secubox-streamlit/README.md`**

Insert before `## License`:

```markdown
## Version pinning via Gitea

The 30 directory-form Streamlit apps under `/srv/streamlit/apps/` are
mirrored in Gitea as `gandalf/streamlit-<appname>`, each with a `v1.0.0`
tag on the initial state.

Deploy a specific version:

```bash
sudo streamlitctl deploy <app> --from-gitea --tag v1.0.0
```

Rollback to the most recent backup:

```bash
sudo streamlitctl rollback <app>
```

After a deploy, `/srv/streamlit/apps/<app>/.deploy.json` records the
current tag and deployment timestamp; the API surfaces them via the
`current_tag` and `deployed_at` fields in `/api/v1/streamlit/apps`.

To re-run the ingest (or pick up newly added apps):

```bash
bash scripts/streamlit-ingest.sh
```
```

- [ ] **Step 3: Add Session 163 entry to `.claude/WIP.md`** (sync to master first to know the right session number)

```bash
bash scripts/agent-worktree.sh sync 95 2>&1 | tail -3
head -3 .claude/WIP.md
```

Then edit `.claude/WIP.md` — replace the top `*Mis à jour ...*` line and insert a new block at the top:

```markdown
# WIP — Work In Progress
*Mis à jour : 2026-05-12 (Session 163)*

---

## ✅ Session 163: Streamlit Gitea version pinning (Issue #95, sub-F of #49)

### Objective
Mirror the 30 directory-form Streamlit apps from `/srv/streamlit/apps/` into Gitea as `gandalf/streamlit-<app>` with `v1.0.0` tag, then extend `streamlitctl` with `--from-gitea --tag` deploy and `rollback` subcommands, plus surface `current_tag` / `deployed_at` in the FastAPI.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-streamlit-gitea-version-pinning-design.md`
- Plan (8 tasks) → `docs/superpowers/plans/2026-05-12-streamlit-gitea-version-pinning.md`
- Per-app ingest function reusing the metablog patterns (gitea@ SSH, idempotent retarget+push or git init)
- Orchestrator with preflights + JSON report (`output/streamlit-ingest-report.json`)
- 3-app smoke + idempotent re-run
- Full 30-app run — see `docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md`
- `streamlitctl deploy <app> --from-gitea --tag <vX.Y.Z>` — clone + replace in-place with backup; auto-prune to 3 most recent backups; restart running instance
- `streamlitctl rollback <app>` — promote latest `.bak.*` back to current, move current aside as `<app>.bak.rolledback.<ts>`
- FastAPI enriches `/apps` with `current_tag` (from `.deploy.json` or `git describe --tags --exact-match`) and `deployed_at`
- Deploy/rollback cycle smoke test (canary: `yijing` at `v1.0.0`)

### Followups
- Sub-projects C, D, E of #49 remain.
- Webhook-triggered redeploy on Gitea tag push (sub-E, separate scope).
```

- [ ] **Step 4: Add the same entry to `.claude/HISTORY.md`** under `## 2026-05-12`, before the previous Session entry, in the same style as existing entries.

- [ ] **Step 5: Commit**

```bash
git add .gitignore packages/secubox-streamlit/README.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs(streamlit): Session 163 — Streamlit Gitea version pinning (ref #95)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Finish worktree — PR `Refs #49 sub-F, Closes #95`

**Files:** none modified — git operations only.

- [ ] **Step 1: Verify branch + clean tree**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/95-streamlit-per-site-version-pinning-conta
git rev-parse --abbrev-ref HEAD
git status --short
```

Expected: branch is right, nothing dirty.

- [ ] **Step 2: Run both smoke tests one final time**

```bash
bash tests/scripts/test-streamlit-ingest.sh 2>&1 | tail -5
bash tests/scripts/test-streamlit-deploy-tag.sh 2>&1 | tail -5
```

Expected: both end with `PASS: all ... passed`. If anything regressed, STOP.

- [ ] **Step 3: Push + open PR**

```bash
bash scripts/agent-worktree.sh finish 2>&1 | tail -5
```

Expected: prints a new PR URL (e.g., `https://github.com/CyberMind-FR/secubox-deb/pull/<N>`).

- [ ] **Step 4: Set PR body via REST API** (because `gh pr edit` is broken by the GraphQL warning per PR #93's experience)

```bash
PR=<N from step 3>
gh api -X PATCH /repos/CyberMind-FR/secubox-deb/pulls/$PR \
  -f title="Streamlit Gitea version pinning: 30 apps (Refs #49 sub-F, closes #95)" \
  -f body="$(cat <<EOF
Sub-project **F** of #49. Closes #95.

## What is live

30 directory-form Streamlit apps from \`/srv/streamlit/apps/\` are mirrored in Gitea as \`gandalf/streamlit-<app>\` with \`v1.0.0\` tag on the initial state. \`streamlitctl deploy <app> --from-gitea --tag <vX.Y.Z>\` performs a clone+replace in-place deploy with backup; \`streamlitctl rollback <app>\` reverts to the latest backup. FastAPI \`/api/v1/streamlit/apps\` now surfaces \`current_tag\` and \`deployed_at\` per app.

## Pieces

- Spec — \`docs/superpowers/specs/2026-05-12-streamlit-gitea-version-pinning-design.md\`
- Plan — \`docs/superpowers/plans/2026-05-12-streamlit-gitea-version-pinning.md\` (8 tasks)
- Per-app ingest — \`scripts/lib/streamlit-ingest-app.sh\`
- Orchestrator — \`scripts/streamlit-ingest.sh\`
- streamlitctl extensions — \`packages/secubox-streamlit/scripts/streamlitctl\` (\`--from-gitea --tag\`, \`rollback\`)
- API enrichment — \`packages/secubox-streamlit/api/main.py\` (\`current_tag\`, \`deployed_at\`)
- Smoke tests — \`tests/scripts/test-streamlit-ingest.sh\`, \`tests/scripts/test-streamlit-deploy-tag.sh\`
- Run record — \`docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md\`

## Decisions (locked in spec)

- All 30 directory-form apps → \`gandalf/streamlit-<app>\` on Gitea
- 23 with \`.git/\` retarget + force-with-lease push (preserves local commits); 7 git init + push
- Deploy model: clone+replace in-place with backup (\`<app>.bak.<ts>\`), max 3 backups retained
- No multi-version side-by-side, no container-per-version (YAGNI)
- Auth: same SSH key path enrolled in B (#97) — no new tokens
- Rollback: latest \`.bak\` promoted to current; current moved aside as \`<app>.bak.rolledback.<ts>\`
EOF
)" >/dev/null
echo "PR #$PR body updated"
```

- [ ] **Step 5: Comment on #49 with progress**

```bash
gh issue comment 49 --body "Sub-project F (Streamlit Gitea version pinning) merged via PR #$PR.

30 Streamlit apps are now in \`gandalf/streamlit-*\` on \`gitea.gk2.secubox.in\` with \`v1.0.0\` tag each. \`streamlitctl deploy <app> --from-gitea --tag <vX.Y.Z>\` + \`rollback\` are live; FastAPI surfaces \`current_tag\`/\`deployed_at\`.

C (site.json schema), D (Dashboard), E (deploy webhook) remain on #49."
```

---

## Self-review

**1. Spec coverage:**

- Spec § *Component 1 — Streamlit app ingest* → Tasks 1 + 2 + 3 + 4 ✓
- Spec § *Component 2 — Deploy with --tag* → Task 5 (`cmd_deploy` + `deploy_from_gitea`) ✓
- Spec § *Component 3 — current_tag in API* → Task 6 ✓
- Spec § *Component 4 — Rollback* → Task 5 (`cmd_rollback`) + Task 7 (smoke verifies the rollback sentinel) ✓
- Spec § *Validation gate* → Task 7 covers 4-6 of the 6 gates; Task 4 covers gates 1-3 (full ingest report + Gitea repo listing + tag check) ✓
- Spec § *Error handling* → mapped to the orchestrator's status keywords + `deploy_from_gitea`'s pre-checks + restore-on-clone-fail ✓
- Spec § *Files* table — Tasks 1, 2, 5, 6, 3, 7, 8 cover each entry ✓

**2. Placeholder scan:**

- No "TBD" / "TODO" / "implement later".
- Task 2 Step 2 says "if `gitea-ssh-preflight.sh` does not exist, cherry-pick `06d35317` or copy verbatim" — this is a real branch state question, mitigated by the inline check command. Acceptable.
- Task 7 references the existing `streamlitctl status` command — verify in Step 1 of Task 5 that the function it calls (`cmd_status`) matches what the existing script actually exposes; rename in the heredoc if needed.

**3. Type / identifier consistency:**

- Function `ingest_streamlit_app` consistent across Tasks 1, 2, 3.
- `GITEA_SSH_USER=gitea`, `GITEA_REPO_OWNER=gandalf`, repo prefix `streamlit-`, port `2222`, LXC host `192.168.1.200` consistent.
- `.deploy.json` schema (`tag`, `deployed_at`, `previous_backup`) consistent across Tasks 5 and 6.
- Backup naming `<app>.bak.<ts>` and rollback sentinel `<app>.bak.rolledback.<ts>` consistent across Tasks 5 and 7.
- API field names `current_tag` and `deployed_at` consistent across Tasks 6 and 7.

No gaps. Plan ready to execute.
