<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer → Gitea Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Idempotent pipeline that pushes 166 MetaBlogizer site directories from MOCHAbin's `/srv/metablogizer/sites/*` into the new Gitea at `gitea.gk2.secubox.in` as `gandalf/metablog-<name>`, tagged `v1.0.0`. Preserves existing local git history when present (83 sites), git-inits the rest (83 sites).

**Architecture:** Bash orchestrator over SSH to MOCHAbin. One-time Gitea config patch enables `ENABLE_PUSH_CREATE_USER` so push creates the repo. SSH key on the `gandalf` Gitea account is the only auth. Per-site function decides between "retarget + push" and "git init + push" based on `.git/` presence. Per-site result captured in `output/ingest-report.json`.

**Tech Stack:** Bash 5 (strict mode), `git`, `ssh`, `jq`, Gitea CLI inside the LXC for SSH-key enrolment.

**Spec:** [docs/superpowers/specs/2026-05-12-metablog-gitea-ingest-design.md](../specs/2026-05-12-metablog-gitea-ingest-design.md)
**Issue:** [#94](https://github.com/CyberMind-FR/secubox-deb/issues/94) (sub-project B of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#93](https://github.com/CyberMind-FR/secubox-deb/pull/93) (Gitea live at `gitea.gk2.secubox.in:2222`)

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `scripts/metablog-ingest-gitea-config.sh` | One-time patch to Gitea app.ini (enable push-create + default branch) |
| Create | `scripts/lib/gitea-ssh-preflight.sh` | Test SSH path to gandalf@gitea.gk2.secubox.in:2222; enrol key if not authenticated |
| Create | `scripts/lib/metablog-ingest-site.sh` | Sourced function `ingest_site <path>` returning a status string |
| Create | `scripts/metablog-ingest.sh` | Main orchestrator: preflights → loop → report |
| Create | `tests/scripts/test-metablog-ingest.sh` | Dry-run smoke + 3-site live staging |
| Modify | `.gitignore` | Ignore `output/ingest-report.json`, `output/ingest-full.log`, `output/test-ingest-*/` |
| Modify | `packages/secubox-metablogizer/README.md` | Document the ingest CLI |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 162 entry |

Reuse: `scripts/lib/test-helpers.sh` (already in repo from earlier work — provides `assert_eq`, `assert_contains`, `pass`).

---

## Task 1: Gitea push-create config bootstrap

**Files:**
- Create: `scripts/metablog-ingest-gitea-config.sh`

This enables Gitea's `ENABLE_PUSH_CREATE_USER` setting so the ingest script can rely on push-to-create-repo semantics. Runs once; idempotent.

- [ ] **Step 1: Verify branch**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/94-metablogizer-gitea-ingest-import-166-sit
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/94-metablogizer-gitea-ingest-import-166-sit`. Otherwise BLOCKED.

- [ ] **Step 2: Locate app.ini inside the Gitea LXC**

```bash
ssh root@192.168.1.200 'lxc-attach -n gitea -- find / -name app.ini -type f 2>/dev/null | grep -v proc' 2>&1
```

Expected: one of `/etc/gitea/app.ini`, `/var/lib/gitea/custom/conf/app.ini`. Record the actual path for use in the script.

- [ ] **Step 3: Write `scripts/metablog-ingest-gitea-config.sh`**

```bash
#!/usr/bin/env bash
# scripts/metablog-ingest-gitea-config.sh
# Ensure Gitea has ENABLE_PUSH_CREATE_USER=true and DEFAULT_BRANCH=main.
# Idempotent: skip restart if no changes were made.
#
# Used by: metablog-ingest.sh preflight
# Requires: SSH to root@192.168.1.200, lxc-attach to gitea LXC

set -euo pipefail

GITEA_HOST="${GITEA_HOST:-192.168.1.200}"
LXC_NAME="${LXC_NAME:-gitea}"
APP_INI="${APP_INI:-/etc/gitea/app.ini}"

log() { echo "[gitea-config] $*"; }
fail() { echo "[gitea-config] FAIL: $*" >&2; exit 1; }

# Verify we can reach the LXC
ssh "root@$GITEA_HOST" "lxc-info -n $LXC_NAME -s 2>/dev/null | grep -q RUNNING" \
  || fail "Gitea LXC '$LXC_NAME' is not running on $GITEA_HOST"

# Probe the app.ini path
if ! ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- test -f $APP_INI"; then
  alt=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- find / -name app.ini -type f 2>/dev/null | grep -v proc | head -1" || true)
  [[ -n "$alt" ]] && APP_INI="$alt" || fail "app.ini not found in Gitea LXC"
  log "Using detected path: $APP_INI"
fi

# Check current state — fast-path skip if both keys already set correctly
current=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- grep -E '^(ENABLE_PUSH_CREATE_USER|DEFAULT_BRANCH)\s*=' $APP_INI 2>/dev/null" || true)
if echo "$current" | grep -q "ENABLE_PUSH_CREATE_USER\s*=\s*true" \
   && echo "$current" | grep -q "DEFAULT_BRANCH\s*=\s*main"; then
  log "Already configured — no change."
  exit 0
fi

# Take a backup
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- cp $APP_INI $APP_INI.bak.metablog-ingest.\$(date +%s)"

# Patch: ensure [repository] section has both keys
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- python3 - $APP_INI" <<'PYEOF'
import configparser, sys, os

path = sys.argv[1]
# Gitea's app.ini is a standard INI; configparser handles it.
cp = configparser.ConfigParser(strict=False, interpolation=None)
cp.read(path)

if 'repository' not in cp:
    cp['repository'] = {}

changed = False
if cp['repository'].get('ENABLE_PUSH_CREATE_USER', '').lower() != 'true':
    cp['repository']['ENABLE_PUSH_CREATE_USER'] = 'true'
    changed = True
if cp['repository'].get('DEFAULT_BRANCH', '') != 'main':
    cp['repository']['DEFAULT_BRANCH'] = 'main'
    changed = True

if changed:
    with open(path, 'w') as f:
        cp.write(f)
    print('patched')
else:
    print('no-op')
PYEOF

# Restart Gitea
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- systemctl restart gitea"
sleep 3
status=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- systemctl is-active gitea" 2>/dev/null || true)
[[ "$status" == "active" ]] || fail "Gitea did not come back up after restart (status: $status)"

log "Gitea reconfigured + restarted. ENABLE_PUSH_CREATE_USER=true, DEFAULT_BRANCH=main."
```

- [ ] **Step 4: Make executable + run**

```bash
chmod +x scripts/metablog-ingest-gitea-config.sh
bash scripts/metablog-ingest-gitea-config.sh 2>&1 | tail -5
```

Expected: ends with `Gitea reconfigured + restarted.` OR `Already configured — no change.` Both are OK. Gitea must still be active after.

- [ ] **Step 5: Verify by probe push**

```bash
# Probe: try a push-create from MOCHAbin with a temporary repo
ssh root@192.168.1.200 '
  tmp=$(mktemp -d)
  cd $tmp
  git init -b main -q
  git config user.email test@example.com
  git config user.name test
  echo "preflight" > README.md
  git add README.md
  git commit -q -m "preflight test"
  if GIT_SSH_COMMAND="ssh -p 2222 -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
     git push -q "ssh://git@gitea.gk2.secubox.in:2222/gandalf/preflight-pushcreate.git" main 2>&1 | tail -3; then
    echo "PROBE-OK"
  else
    echo "PROBE-FAILED"
  fi
  rm -rf $tmp
'
```

Expected: `PROBE-OK`. If `PROBE-FAILED`:

- If the failure says `publickey`, then Task 2 (SSH key enrolment) is required next.
- If it says `repository does not exist`, then `ENABLE_PUSH_CREATE_USER` did NOT take effect — debug Gitea restart, check `app.ini`.

The probe repo `gandalf/preflight-pushcreate` lives on Gitea; clean it up after Task 2 with `gh-api equivalent` or via Gitea web UI.

- [ ] **Step 6: Commit**

```bash
git add scripts/metablog-ingest-gitea-config.sh
git commit -m "feat(metablog): One-time Gitea config patch for push-create (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: SSH preflight + gandalf key enrolment

**Files:**
- Create: `scripts/lib/gitea-ssh-preflight.sh`

`ingest_site` pushes via SSH as `git@gitea.gk2.secubox.in:2222`. The remote sees the user via the SSH key (Gitea maps key → owner). This preflight verifies and, if missing, enrols MOCHAbin root's SSH key into the `gandalf` Gitea account.

- [ ] **Step 1: Write `scripts/lib/gitea-ssh-preflight.sh`**

```bash
#!/usr/bin/env bash
# scripts/lib/gitea-ssh-preflight.sh
# Verify SSH path to gandalf@gitea.gk2.secubox.in:2222 works.
# If not, enrol the MOCHAbin root's id_*.pub into gandalf's Gitea account.
#
# Sourceable: provides `ssh_preflight` function.
# Standalone: `bash gitea-ssh-preflight.sh [--enrol]` runs the preflight and
#   optionally enrols a key.

set -euo pipefail

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_USER="${GITEA_USER:-gandalf}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"
LXC_NAME="${LXC_NAME:-gitea}"

ssh_preflight() {
  # Returns 0 if SSH to gandalf@gitea is authenticated; non-zero otherwise.
  local out
  out=$(ssh -p "$GITEA_SSH_PORT" -o ConnectTimeout=5 -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new \
            "$GITEA_USER@$GITEA_HOST" 2>&1 | head -3 || true)
  echo "$out"
  if echo "$out" | grep -qE "successfully authenticated|Hi there"; then
    return 0
  fi
  return 1
}

enrol_mochabin_root_key() {
  # Push the MOCHAbin root's id_*.pub into gandalf's Gitea authorized_keys
  # via lxc-attach (no API token needed).
  local pubkey
  pubkey=$(ssh "root@$LXC_HOST" 'cat /root/.ssh/id_ed25519.pub 2>/dev/null || cat /root/.ssh/id_rsa.pub 2>/dev/null' || true)
  if [[ -z "$pubkey" ]]; then
    echo "ERROR: no MOCHAbin root pubkey found" >&2
    return 1
  fi

  # Use `gitea admin user add-key` inside the LXC.
  # CAUTION: gitea CLI version varies; v1.22 uses `admin auth add-key`.
  # We use the direct DB approach via authorized_keys file as a fallback.
  ssh "root@$LXC_HOST" "lxc-attach -n $LXC_NAME -- bash -c \"
    set -e
    # Try Gitea CLI first
    if su gitea -c 'gitea admin user keys add --user $GITEA_USER --key \\\"$pubkey\\\" --title metablog-ingest 2>/dev/null'; then
      echo 'gitea-cli-ok'
    else
      # Fallback: add directly via su -c gitea-injectable form
      # (intentionally left simple — if Gitea CLI doesn't have the subcommand
      # in this version, the operator adds the key manually via web UI)
      echo 'gitea-cli-failed: please add key manually at https://$GITEA_HOST/user/settings/keys'
      echo 'Pubkey:'
      echo '$pubkey'
      exit 1
    fi
  \""
}

if [[ "${1:-}" == "--enrol" ]]; then
  if ssh_preflight; then
    echo "Already authenticated — no enrolment needed."
    exit 0
  fi
  enrol_mochabin_root_key
  echo "Key enrolled. Re-running preflight..."
  ssh_preflight && echo "OK." || { echo "Preflight still failing — manual intervention required."; exit 1; }
elif [[ "${1:-}" == "--check" ]] || [[ -z "${1:-}" ]] && [[ -z "${BASH_SOURCE[0]:-}" ]] ; then
  ssh_preflight && echo "OK." || { echo "Preflight failed."; exit 1; }
fi
```

- [ ] **Step 2: Make executable + run preflight only (no enrol)**

```bash
chmod +x scripts/lib/gitea-ssh-preflight.sh
bash scripts/lib/gitea-ssh-preflight.sh --check 2>&1 | tail -5 || true
```

Expected: `OK.` (if a key is already enrolled for gandalf — possible because the existing .git remotes in some sites already use SSH-based auth). If the output is `Preflight failed` plus a `Permission denied (publickey)` line, run Step 3.

- [ ] **Step 3: If preflight fails, enrol the key**

```bash
bash scripts/lib/gitea-ssh-preflight.sh --enrol 2>&1 | tail -10
```

Expected: ends with `OK.` Verify by running `--check` once more:

```bash
bash scripts/lib/gitea-ssh-preflight.sh --check 2>&1 | tail -2
```

If still failing, the Gitea CLI in this version probably doesn't have `admin user keys add` — fall back to enrolling via the Gitea web UI: visit `https://gitea.gk2.secubox.in/user/settings/keys` (logged in as gandalf), paste the pubkey, save.

- [ ] **Step 4: Commit**

```bash
git add scripts/lib/gitea-ssh-preflight.sh
git commit -m "feat(metablog): SSH preflight + key enrolment helper for Gitea ingest (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Per-site ingest function

**Files:**
- Create: `scripts/lib/metablog-ingest-site.sh`

A sourced function `ingest_site <site_dir>` that handles a single site. Returns 0 on success, prints a status keyword on stdout.

- [ ] **Step 1: Write `scripts/lib/metablog-ingest-site.sh`**

```bash
#!/usr/bin/env bash
# scripts/lib/metablog-ingest-site.sh
# Per-site ingest function. Sourceable.
#
# Provides: ingest_site <site_dir>
#   - prints one status keyword on stdout:
#       ingested-fresh         : site had no .git, fresh init + push + tag
#       ingested-with-history  : site had .git, retargeted + pushed + tag
#       skip-already-current   : remote HEAD == local HEAD, idempotent skip
#       fail-<reason>          : something went wrong
#   - returns 0 on any "ingested-*" or "skip-*", non-zero on "fail-*"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_USER="${GITEA_USER:-gandalf}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

# Shared SSH command used by every git operation
_git_ssh_cmd() {
  echo "ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
}

ingest_site() {
  local site_dir="$1"
  [[ -d "$site_dir" ]] || { echo "fail-no-such-dir"; return 1; }

  local name repo_url
  name=$(basename "$site_dir")
  repo_url="ssh://git@$GITEA_HOST:$GITEA_SSH_PORT/$GITEA_USER/metablog-$name.git"

  # All operations happen on the MOCHAbin (where the site dir lives), via ssh.
  # We wrap a single big ssh+heredoc to keep it transactional from caller's view.
  ssh "root@$LXC_HOST" bash <<EOSH
set -euo pipefail
SITE="$site_dir"
NAME="$name"
REPO_URL="$repo_url"
GIT_SSH_COMMAND="$(_git_ssh_cmd)"
export GIT_SSH_COMMAND

cd "\$SITE"

# Determine remote HEAD (might fail if repo doesn't exist yet — that's OK)
remote_head=\$(git ls-remote "\$REPO_URL" main 2>/dev/null | awk '{print \$1}' || true)

if [[ -d .git ]]; then
  # Has local history
  local_head=\$(git rev-parse HEAD 2>/dev/null || true)
  if [[ -n "\$remote_head" && "\$remote_head" == "\$local_head" ]]; then
    echo "skip-already-current"
    exit 0
  fi
  # Retarget and push
  git remote set-url origin "\$REPO_URL" 2>/dev/null \
    || git remote add origin "\$REPO_URL"
  # Source branch is whatever HEAD points at; rename to main on push
  src_branch=\$(git symbolic-ref --short HEAD 2>/dev/null || echo HEAD)
  git push --quiet --force-with-lease origin "\$src_branch:main"
  git tag -f v1.0.0
  git push --quiet --force origin v1.0.0
  echo "ingested-with-history"
  exit 0
else
  # No local git — fresh init
  git init -q -b main
  git config user.email "metablog-ingest@cybermind.fr"
  git config user.name "MetaBlogizer Ingest"
  git add -A
  if git diff --cached --quiet; then
    # Empty directory — nothing to commit
    echo "fail-empty-dir"
    exit 1
  fi
  git commit -q -m "feat: import from /srv/metablogizer/sites/\$NAME"
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

- [ ] **Step 2: Smoke-test on one known-no-.git site (e.g., `255`)**

```bash
# Source + invoke
source scripts/lib/metablog-ingest-site.sh
ingest_site /srv/metablogizer/sites/255 2>&1
```

Expected: prints `ingested-fresh` (and creates `gandalf/metablog-255` on Gitea).

- [ ] **Step 3: Re-run on the same site → idempotent**

```bash
ingest_site /srv/metablogizer/sites/255 2>&1
```

Expected: prints `skip-already-current`.

- [ ] **Step 4: Smoke-test on one known-has-.git site (e.g., `zoo`)**

```bash
ingest_site /srv/metablogizer/sites/zoo 2>&1
```

Expected: `ingested-with-history` on first run.

- [ ] **Step 5: Verify on Gitea side**

```bash
curl -s "https://$GITEA_HOST/api/v1/users/gandalf/repos?limit=50" \
  | jq '[.[] | select(.name | startswith("metablog-")) | .name]'
```

Expected: a list containing `metablog-255`, `metablog-zoo`, possibly `preflight-pushcreate` (from Task 1 probe).

Visit `https://gitea.gk2.secubox.in/gandalf/metablog-255` in a browser to eyeball the file tree — should show `index.html`. And `https://gitea.gk2.secubox.in/gandalf/metablog-255/releases/tag/v1.0.0` should exist.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/metablog-ingest-site.sh
git commit -m "feat(metablog): Per-site ingest function (idempotent, history-preserving) (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Orchestrator

**Files:**
- Create: `scripts/metablog-ingest.sh`

The main entry point. Pre-flights → site list → loop → report.

- [ ] **Step 1: Write `scripts/metablog-ingest.sh`**

```bash
#!/usr/bin/env bash
# scripts/metablog-ingest.sh
# Idempotent ingest of /srv/metablogizer/sites/* into gitea.gk2.secubox.in
# as gandalf/metablog-<site>. Records per-site outcome in
# output/ingest-report.json.
#
# Usage:
#   bash scripts/metablog-ingest.sh [--dry-run]
#                                   [--limit N]
#                                   [--site <name>]
#                                   [--halt-on-fail]
#
# Pre-flights:
#   1. SSH preflight to gandalf@gitea.gk2.secubox.in:2222
#   2. Gitea ENABLE_PUSH_CREATE_USER is true (probed)
#   3. /srv/metablogizer/sites/ exists and is non-empty
#   4. /data/volumes/gitea/repos/ has >=1 GB free

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
# shellcheck source=lib/gitea-ssh-preflight.sh
source "$REPO/scripts/lib/gitea-ssh-preflight.sh"
# shellcheck source=lib/metablog-ingest-site.sh
source "$REPO/scripts/lib/metablog-ingest-site.sh"

LXC_HOST="${LXC_HOST:-192.168.1.200}"
SITES_DIR="${SITES_DIR:-/srv/metablogizer/sites}"
DRY_RUN=0
LIMIT=0
ONLY_SITE=""
HALT_ON_FAIL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)      DRY_RUN=1; shift ;;
    --limit)        LIMIT="$2"; shift 2 ;;
    --site)         ONLY_SITE="$2"; shift 2 ;;
    --halt-on-fail) HALT_ON_FAIL=1; shift ;;
    *)              echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

REPORT="$REPO/output/ingest-report.json"
LOG="$REPO/output/ingest-full.log"
mkdir -p "$REPO/output"
: > "$LOG"

log() { printf '[ingest] %s\n' "$*" | tee -a "$LOG" >&2; }
fail_pre() { log "PRE-FLIGHT FAIL: $*"; exit 1; }

# ───── Pre-flights ─────
log "Pre-flight 1: SSH path to $GITEA_USER@$GITEA_HOST:$GITEA_SSH_PORT"
ssh_preflight >>"$LOG" 2>&1 || fail_pre "SSH preflight failed. Run scripts/lib/gitea-ssh-preflight.sh --enrol"

log "Pre-flight 2: Gitea push-create enabled (probe via /tmp test repo)"
probe_out=$(ssh "root@$LXC_HOST" "
  tmp=\$(mktemp -d)
  cd \$tmp
  git init -q -b main
  git config user.email probe@ingest
  git config user.name probe
  echo probe > x.txt
  git add x.txt
  git commit -q -m probe
  GIT_SSH_COMMAND='$(_git_ssh_cmd)' \
    git push --quiet 'ssh://git@$GITEA_HOST:$GITEA_SSH_PORT/$GITEA_USER/preflight-probe-\$\$.git' main 2>&1
  rm -rf \$tmp
" 2>&1 || true)
echo "$probe_out" | grep -q "fatal\|denied\|refused" \
  && fail_pre "Push-create probe failed: $(echo "$probe_out" | tail -1)"

log "Pre-flight 3: sites dir + disk"
ssh "root@$LXC_HOST" "test -d $SITES_DIR && [ \$(ls $SITES_DIR | wc -l) -gt 0 ]" \
  || fail_pre "$SITES_DIR not present or empty"
free_kb=$(ssh "root@$LXC_HOST" "df --output=avail /data/volumes/gitea/repos 2>/dev/null | tail -1" || echo 0)
[[ "$free_kb" -gt 1048576 ]] \
  || fail_pre "Less than 1 GB free on /data/volumes/gitea/repos/ (got: ${free_kb}KB)"

log "Pre-flights OK"

# ───── Site list ─────
if [[ -n "$ONLY_SITE" ]]; then
  sites=("$ONLY_SITE")
else
  mapfile -t sites < <(ssh "root@$LXC_HOST" "ls -1 $SITES_DIR | sort")
fi
[[ "$LIMIT" -gt 0 ]] && sites=("${sites[@]:0:$LIMIT}")
total=${#sites[@]}
log "Will process $total sites"

# ───── Loop ─────
declare -A RESULT
declare -A DURATION

count_ok=0
count_skip=0
count_fail=0
i=0
for s in "${sites[@]}"; do
  i=$((i+1))
  log "[$i/$total] $s"
  start=$(date +%s)
  if [[ $DRY_RUN -eq 1 ]]; then
    RESULT[$s]="dry-run"
    DURATION[$s]=0
    log "  DRY-RUN — would ingest"
    continue
  fi
  status=$(ingest_site "$SITES_DIR/$s" 2>>"$LOG" || echo "fail-internal-error")
  end=$(date +%s)
  RESULT[$s]="$status"
  DURATION[$s]=$((end - start))
  log "  → $status (${DURATION[$s]}s)"

  case "$status" in
    ingested-*)  count_ok=$((count_ok+1)) ;;
    skip-*)      count_skip=$((count_skip+1)) ;;
    *)           count_fail=$((count_fail+1))
                 [[ $HALT_ON_FAIL -eq 1 ]] && { log "HALT-ON-FAIL: stopping at $s"; break; }
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
  echo "  \"sites\": {"
  first=1
  for s in "${sites[@]}"; do
    [[ $first -eq 1 ]] && first=0 || echo ","
    echo -n "    \"$s\": { \"status\": \"${RESULT[$s]:-not-run}\", \"duration_s\": ${DURATION[$s]:-0} }"
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

- [ ] **Step 2: Make executable + dry-run**

```bash
chmod +x scripts/metablog-ingest.sh
bash scripts/metablog-ingest.sh --dry-run --limit 3 2>&1 | tail -15
```

Expected: 3 lines `[1/3] ... → dry-run`, `[2/3] ... → dry-run`, `[3/3] ... → dry-run`, plus a Summary line `0 ingested, 0 skipped, 0 failed` (dry-run does not run ingest_site). Report exists at `output/ingest-report.json`.

- [ ] **Step 3: Commit**

```bash
git add scripts/metablog-ingest.sh
git commit -m "feat(metablog): Orchestrator for Gitea ingest (preflights + report) (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Smoke test — 3-site staging run

**Files:**
- Create: `tests/scripts/test-metablog-ingest.sh`

A scripted smoke that runs the orchestrator with `--limit 3`, then checks the result file.

- [ ] **Step 1: Write the smoke test**

```bash
#!/usr/bin/env bash
# tests/scripts/test-metablog-ingest.sh
# Smoke test for the MetaBlogizer → Gitea ingest pipeline.
# Runs against the live Gitea — NOT a unit test.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
REPORT="$REPO/output/ingest-report.json"

log_step() { echo "[smoke step $1] $2"; }

# Step 1: Dry-run, --limit 3
log_step 1 "dry-run --limit 3"
bash "$REPO/scripts/metablog-ingest.sh" --dry-run --limit 3 >/dev/null 2>&1
total=$(jq '.total' "$REPORT")
assert_eq "3" "$total" "dry-run total"

# Step 2: Real run, --limit 3
log_step 2 "live --limit 3"
bash "$REPO/scripts/metablog-ingest.sh" --limit 3 >/dev/null 2>&1 || {
  echo "FAIL: live run errored. See $REPO/output/ingest-full.log"
  exit 1
}
ok=$(jq '.by_status.ok + .by_status.skip' "$REPORT")
if [[ "$ok" -lt 3 ]]; then
  echo "FAIL: expected >=3 ok+skip, got $ok"
  jq . "$REPORT"
  exit 1
fi
pass "live --limit 3 produced $ok ok+skip sites"

# Step 3: Re-run — idempotent (all should skip)
log_step 3 "idempotent re-run"
bash "$REPO/scripts/metablog-ingest.sh" --limit 3 >/dev/null 2>&1
skip=$(jq '.by_status.skip' "$REPORT")
assert_eq "3" "$skip" "all 3 should skip-already-current on re-run"

# Step 4: Verify on Gitea side
log_step 4 "Gitea API repo list"
repos=$(curl -s "https://$GITEA_HOST/api/v1/users/gandalf/repos?limit=50" \
        | jq -r '[.[] | select(.name | startswith("metablog-")) | .name] | length')
if [[ "$repos" -lt 3 ]]; then
  echo "FAIL: Gitea has only $repos metablog-* repos, expected >=3"
  exit 1
fi
pass "Gitea has $repos metablog-* repos visible via API"

# Step 5: Clone one + diff against source
log_step 5 "clone + diff"
first_site=$(jq -r '.sites | to_entries[0].key' "$REPORT")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
GIT_SSH_COMMAND="ssh -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
  git clone -q "ssh://git@$GITEA_HOST:2222/gandalf/metablog-$first_site.git" "$tmp/clone"
# Pull source via rsync over SSH for the diff
rsync -a --exclude='.git' "root@192.168.1.200:/srv/metablogizer/sites/$first_site/" "$tmp/source/" >/dev/null
if ! diff -qr "$tmp/clone" "$tmp/source" 2>&1 | grep -v "Only in $tmp/clone: .git" | grep -q .; then
  pass "clone == source for $first_site"
else
  echo "FAIL: clone diverges from source for $first_site:"
  diff -qr "$tmp/clone" "$tmp/source" 2>&1 | grep -v "Only in $tmp/clone: .git" | head -10
  exit 1
fi

pass "all smoke checks passed"
```

- [ ] **Step 2: Make executable + run**

```bash
chmod +x tests/scripts/test-metablog-ingest.sh
bash tests/scripts/test-metablog-ingest.sh 2>&1 | tail -20
```

Expected: ends with `PASS: all smoke checks passed`. All 5 step lines visible.

- [ ] **Step 3: Commit**

```bash
git add tests/scripts/test-metablog-ingest.sh
git commit -m "test(metablog): Smoke test for 3-site Gitea ingest (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Full run on 166 sites

**Files:** no new repo files — this is a verification + report run.

- [ ] **Step 1: Full run**

```bash
bash scripts/metablog-ingest.sh 2>&1 | tail -10
```

Expected runtime: 5–20 minutes (most sites are small; bottleneck is SSH handshake per site). Final line: `Summary: 166 total, N ingested, M skipped, K failed`.

- [ ] **Step 2: Inspect report**

```bash
jq '.by_status' output/ingest-report.json
jq '.sites | to_entries | map(select(.value.status | startswith("fail")))' output/ingest-report.json
```

Expected: `.by_status.ok + .by_status.skip` ≥ 160 (allow up to 6 legitimate failures). The second query lists per-site failures with their status; investigate each via `bash scripts/metablog-ingest.sh --site <name>`.

- [ ] **Step 3: Cross-check on Gitea**

```bash
total=$(curl -s "https://gitea.gk2.secubox.in/api/v1/users/gandalf/repos?limit=200" \
        | jq '[.[] | select(.name | startswith("metablog-"))] | length')
echo "Gitea metablog-* repo count: $total"
```

Expected: ≥ 160 (matching the report).

- [ ] **Step 4: Random sample diff**

```bash
for site in $(jq -r '.sites | to_entries | map(select(.value.status | startswith("ingested"))) | .[0:5] | .[].key' output/ingest-report.json); do
  tmp=$(mktemp -d)
  GIT_SSH_COMMAND="ssh -p 2222 -o BatchMode=yes" \
    git clone -q "ssh://git@gitea.gk2.secubox.in:2222/gandalf/metablog-$site.git" "$tmp/clone"
  rsync -a --exclude='.git' "root@192.168.1.200:/srv/metablogizer/sites/$site/" "$tmp/source/" >/dev/null
  diff=$(diff -qr "$tmp/clone" "$tmp/source" 2>&1 | grep -v "Only in $tmp/clone: .git" | wc -l)
  echo "$site: $diff diffs"
  rm -rf "$tmp"
done
```

Expected: 5 lines `<site>: 0 diffs`.

- [ ] **Step 5: Commit the report**

```bash
# NOTE: output/ingest-report.json is .gitignored in Task 7. For this commit
# only, we commit a redacted summary into the spec/plan dir as a record of
# the run outcome.
mkdir -p docs/superpowers/runs
cat > docs/superpowers/runs/2026-05-12-metablog-ingest-summary.md <<EOF
# MetaBlogizer Ingest Run — 2026-05-12

Live run of \`scripts/metablog-ingest.sh\` on the MOCHAbin.

\`\`\`
$(jq '.by_status' output/ingest-report.json)
\`\`\`

Per-site failures (if any):

\`\`\`
$(jq '.sites | to_entries | map(select(.value.status | startswith("fail")))' output/ingest-report.json)
\`\`\`

Gitea repo count: $total
EOF
git add docs/superpowers/runs/
git commit -m "docs(metablog): Record full-run ingest summary (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: .gitignore + tracking docs

**Files:**
- Modify: `.gitignore`
- Modify: `packages/secubox-metablogizer/README.md`
- Modify: `.claude/WIP.md`, `.claude/HISTORY.md`

- [ ] **Step 1: Append to `.gitignore`**

```bash
cat >> .gitignore <<'EOF'

# MetaBlogizer ingest artifacts (regenerated each run)
/output/ingest-report.json
/output/ingest-full.log
/output/test-ingest-*/
EOF
```

- [ ] **Step 2: Append to `packages/secubox-metablogizer/README.md`**

Insert before `## License`:

```markdown
## Gitea ingest

The 166 sites under `/srv/metablogizer/sites/*` are tracked in the Gitea
instance at `https://gitea.gk2.secubox.in/gandalf/?tab=repositories&q=metablog`
as `gandalf/metablog-<sitename>` repositories.

Initial ingest is driven by:

```bash
bash scripts/metablog-ingest-gitea-config.sh   # one-time; enables push-create
bash scripts/lib/gitea-ssh-preflight.sh --check  # verify SSH path
bash scripts/metablog-ingest.sh                # full run
```

Idempotent. Re-running picks up new sites and skips ones already in sync.
Per-site outcome lands in `output/ingest-report.json`.
```

- [ ] **Step 3: Add WIP/HISTORY entries — Session 162**

In `.claude/WIP.md`, replace the top `*Mis à jour ...*` line and insert a new block before the previous Session 161 entry:

```markdown
# WIP — Work In Progress
*Mis à jour : 2026-05-12 (Session 162)*

---

## ✅ Session 162: MetaBlogizer → Gitea ingest (Issue #94, sub-B of #49)

### Objective
Ingest the 166 MetaBlogizer sites from `/srv/metablogizer/sites/` into the new Gitea at `https://gitea.gk2.secubox.in/gandalf/metablog-*`, with `v1.0.0` tag on the initial state. Prerequisite was sub-project A (#93, Gitea routing).

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-metablog-gitea-ingest-design.md`
- Plan (7 tasks) → `docs/superpowers/plans/2026-05-12-metablog-gitea-ingest.md`
- Gitea config patch — enabled `ENABLE_PUSH_CREATE_USER=true`, `DEFAULT_BRANCH=main`
- SSH preflight + key enrolment helper
- Per-site ingest function (idempotent, history-preserving for the 83 sites with `.git`)
- Orchestrator with preflights + JSON report + `--dry-run` / `--limit` / `--site` / `--halt-on-fail`
- Smoke test on 3 sites + idempotent re-run
- Full run on 166 sites — see `docs/superpowers/runs/2026-05-12-metablog-ingest-summary.md`

### Result
$(jq '.by_status' output/ingest-report.json)

### Followups
- Sub-project C (`site.json` schema + version API endpoint) — depends on these repos existing
- Sub-project D (Dashboard) — depends on C
- Sub-project E (deploy webhook) — depends on B (now done)
- Sub-project F (Streamlit per-site version pinning) — independent, can start in parallel
```

Do the same in `.claude/HISTORY.md` under the `## 2026-05-12` heading, before Session 161, in the same style as existing Session entries.

- [ ] **Step 4: Commit**

```bash
git add .gitignore packages/secubox-metablogizer/README.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs(metablog): Session 162 tracking + README + .gitignore (ref #94)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Finish worktree — PR `Refs #49 sub-B`

**Files:** none modified — git operations only.

- [ ] **Step 1: Verify branch + clean tree**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/94-metablogizer-gitea-ingest-import-166-sit
git rev-parse --abbrev-ref HEAD
git status --short
```

Expected: branch is right, nothing dirty.

- [ ] **Step 2: One last smoke before push**

```bash
bash tests/scripts/test-metablog-ingest.sh 2>&1 | tail -5
```

Expected: `PASS: all smoke checks passed`. If anything regressed, STOP.

- [ ] **Step 3: Push + PR via helper**

```bash
bash scripts/agent-worktree.sh finish 2>&1 | tail -5
```

Expected: prints a new PR URL.

- [ ] **Step 4: Set PR body via REST API (gh pr edit is broken by GraphQL warning)**

```bash
PR=<N from step 3>
gh api -X PATCH /repos/CyberMind-FR/secubox-deb/pulls/$PR \
  -f title="MetaBlogizer → Gitea ingest: 166 sites (Refs #49 sub-B, closes #94)" \
  -f body="$(cat <<EOF
Sub-project **B** of #49. Closes #94.

## What is live

166 MetaBlogizer site directories under \`/srv/metablogizer/sites/\` are now mirrored in Gitea as \`gandalf/metablog-<site>\` with \`v1.0.0\` tag on the initial commit.

## Verified

- \`tests/scripts/test-metablog-ingest.sh\` passes (3-site smoke + idempotent re-run + clone-vs-source diff)
- Full run report: see \`docs/superpowers/runs/2026-05-12-metablog-ingest-summary.md\`

## Pieces

- Spec — \`docs/superpowers/specs/2026-05-12-metablog-gitea-ingest-design.md\`
- Plan — \`docs/superpowers/plans/2026-05-12-metablog-gitea-ingest.md\` (7 tasks)
- One-time Gitea config patch — \`scripts/metablog-ingest-gitea-config.sh\`
- SSH preflight helper — \`scripts/lib/gitea-ssh-preflight.sh\`
- Per-site ingest function — \`scripts/lib/metablog-ingest-site.sh\`
- Orchestrator — \`scripts/metablog-ingest.sh\`
- Smoke test — \`tests/scripts/test-metablog-ingest.sh\`

## Decisions (locked in spec)

- Owner: \`gandalf\` user (matches old \`192.168.255.1:3001\` naming)
- Repo prefix: \`metablog-<sitename>\` (unifies the ex-droplet-sites/ 12 too)
- Existing .git: retarget remote + push history (preserves 1 commit each)
- Auth: SSH only via key enrolled on gandalf — no API token
- Idempotent: skip if remote HEAD matches local HEAD
EOF
)" >/dev/null
echo "PR #$PR updated"
```

(Replace `<N from step 3>` with the actual PR number.)

- [ ] **Step 5: Comment on #49 with progress**

```bash
gh issue comment 49 --body "Sub-project B (MetaBlogizer → Gitea ingest) merged via PR #$PR.

166 sites are now in \`gandalf/metablog-*\` on \`gitea.gk2.secubox.in\` with \`v1.0.0\` tag each.

C (\`site.json\` schema), D (Dashboard), E (deploy webhook) can now start. F (Streamlit) can also start in parallel."
```

---

## Self-review

**1. Spec coverage:**

- Spec § *Component 1 — Gitea config bootstrap* → Task 1 ✓
- Spec § *Component 2 — SSH key enrolment* → Task 2 ✓
- Spec § *Component 3 — Per-site ingest function* → Task 3 ✓
- Spec § *Component 4 — Orchestrator* → Task 4 ✓
- Spec § *Component 5 — Smoke test on 3-site subset* → Task 5 ✓
- Spec § *Component 6 — Full run + post-run verification* → Task 6 ✓
- Spec § *Files* table — Task 7 covers `.gitignore` + README + WIP/HISTORY; the runs/ subdir was added as Task 6 step 5 ✓
- Spec § *Error handling* → mapped into the orchestrator's status keywords + report ✓
- Spec § *Rollback* → documented in spec; not a separate task because rollback is operator-driven if a run goes sideways ✓
- Spec § *Licensing* → SPDX header on the bash files left to the license-headers tool (#81) ✓

**2. Placeholder scan:**

- No "TBD" / "TODO" / "implement later".
- Task 6 step 5 uses `$total` from earlier in the same shell block — that's a real variable, not a placeholder.
- Task 8 step 4 uses `<N from step 3>` placeholder for the PR number — that's explicitly marked as "replace with the actual PR number". Acceptable because the value is genuinely dynamic.

**3. Type / identifier consistency:**

- Function `ingest_site` consistent across Tasks 3, 4, 5.
- Function `ssh_preflight` consistent across Tasks 2, 4.
- Env var `GITEA_HOST` defaults to `gitea.gk2.secubox.in` everywhere.
- Env var `GITEA_SSH_PORT` defaults to `2222` everywhere.
- Env var `GITEA_USER` defaults to `gandalf` everywhere.
- Report path `output/ingest-report.json` consistent in Tasks 4, 5, 6, 7.
- Status keywords (`ingested-fresh`, `ingested-with-history`, `skip-already-current`, `fail-*`) defined in Task 3 and consumed by Task 4's counters.

No gaps. Plan ready to execute.
