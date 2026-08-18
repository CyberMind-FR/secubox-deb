#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/streamlit-ingest.sh
# Idempotent ingest of /srv/streamlit/apps/* (directories only) into
# gitea.gk2.secubox.in as gandalf/streamlit-<app>. Records per-app
# outcome in output/streamlit-ingest-report.json.
#
# Usage:
#   bash scripts/streamlit-ingest.sh [--dry-run] [--limit N] [--app <name>] [--halt-on-fail]
#
# Pre-flights:
#   1. SSH preflight to gitea@gitea.gk2.secubox.in:2222 (from MOCHAbin)
#   2. Gitea ENABLE_PUSH_CREATE_USER is true (probed via test push)
#   3. /srv/streamlit/apps/ exists and has directory entries
#   4. /data/volumes/gitea/repos/ has >=1 GB free

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

# Source helpers with $@ cleared so their standalone if/elif guards don't
# misfire on our own flags (e.g. --dry-run would match the "unknown arg" path).
_saved_source_args=( "$@" )
set --
# shellcheck source=lib/gitea-ssh-preflight.sh
source "$REPO/scripts/lib/gitea-ssh-preflight.sh"
# shellcheck source=lib/streamlit-ingest-app.sh
source "$REPO/scripts/lib/streamlit-ingest-app.sh"
set -- "${_saved_source_args[@]}"
unset _saved_source_args

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
  mapfile -t apps < <(ssh "root@$LXC_HOST" "find $APPS_DIR -maxdepth 1 -mindepth 1 -type d ! -name '.*' ! -name '__pycache__' -printf '%f\n' | sort")
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
