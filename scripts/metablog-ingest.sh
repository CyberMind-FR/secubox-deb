#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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
#   1. SSH preflight to gitea@gitea.gk2.secubox.in:2222 (from MOCHAbin)
#   2. Gitea ENABLE_PUSH_CREATE_USER is true (probed by push to a test repo)
#   3. /srv/metablogizer/sites/ exists and is non-empty
#   4. /data/volumes/gitea/repos/ has >=1 GB free

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
# Save and clear positional params before sourcing libs that contain
# standalone argument-parse guards (they check $1 at source time).
_saved_args=("$@"); set --
# shellcheck source=lib/gitea-ssh-preflight.sh
source "$REPO/scripts/lib/gitea-ssh-preflight.sh"
# shellcheck source=lib/metablog-ingest-site.sh
source "$REPO/scripts/lib/metablog-ingest-site.sh"
# Restore positional params for the orchestrator's own arg parsing.
set -- "${_saved_args[@]+"${_saved_args[@]}"}"

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
log "Pre-flight 1: SSH path from MOCHAbin to $GITEA_SSH_USER@$GITEA_HOST:$GITEA_SSH_PORT"
ssh_preflight >>"$LOG" 2>&1 || fail_pre "SSH preflight failed. Run scripts/lib/gitea-ssh-preflight.sh --enrol"

log "Pre-flight 2: Gitea push-create enabled (probe via /tmp test repo)"
_git_ssh_val="$(_git_ssh_cmd)"
probe_out=$(ssh "root@$LXC_HOST" bash <<EOPROBE 2>&1 || true
set -euo pipefail
tmp=\$(mktemp -d)
cd "\$tmp"
git init -q -b main
git config user.email probe@ingest
git config user.name probe
echo probe > x.txt
git add x.txt
git commit -q -m probe
export GIT_SSH_COMMAND='${_git_ssh_val}'
git push --quiet "ssh://${GITEA_SSH_USER}@${GITEA_HOST}:${GITEA_SSH_PORT}/${GITEA_REPO_OWNER}/preflight-probe-\$(date +%s).git" main 2>&1
rm -rf "\$tmp"
EOPROBE
)
if echo "$probe_out" | grep -qE "fatal|denied|refused"; then
  fail_pre "Push-create probe failed: $(echo "$probe_out" | tail -1)"
fi

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
