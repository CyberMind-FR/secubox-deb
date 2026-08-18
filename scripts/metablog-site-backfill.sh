#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/metablog-site-backfill.sh
# Backfill /srv/metablogizer/sites/<name>/site.json with the formal schema.
#
# Usage:
#   bash scripts/metablog-site-backfill.sh [--dry-run] [--force] [--site <name>]
#
# Strategy per site:
#   - missing site.json -> create complete (name, domain, published, version, streamlit_app)
#   - present + --force -> merge missing fields, preserve existing keys/values
#   - present, no --force -> skip
#
# All git/Gitea probes happen on the MOCHAbin via SSH.

set -euo pipefail

LXC_HOST="${LXC_HOST:-192.168.1.200}"
SITES_DIR="${SITES_DIR:-/srv/metablogizer/sites}"
GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
GITEA_REPO_OWNER="${GITEA_REPO_OWNER:-gandalf}"
DOMAIN_SUFFIX="${DOMAIN_SUFFIX:-.gk2.secubox.in}"

DRY_RUN=0
FORCE=0
ONLY_SITE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; shift ;;
    --force)     FORCE=1; shift ;;
    --site)      ONLY_SITE="$2"; shift 2 ;;
    *)           echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
REPORT="$REPO/output/metablog-backfill-report.json"
LOG="$REPO/output/metablog-backfill.log"
mkdir -p "$REPO/output"
: > "$LOG"

log() { printf '[backfill] %s\n' "$*" | tee -a "$LOG" >&2; }

# ───── Build site list ─────
if [[ -n "$ONLY_SITE" ]]; then
  sites=("$ONLY_SITE")
else
  mapfile -t sites < <(ssh "root@$LXC_HOST" "find $SITES_DIR -maxdepth 1 -mindepth 1 -type d ! -name '.*' -printf '%f\n' | sort")
fi
total=${#sites[@]}
log "$total sites to consider (dry_run=$DRY_RUN force=$FORCE)"

declare -A RESULT

count_created=0
count_merged=0
count_skip=0
count_fail=0
i=0
for s in "${sites[@]}"; do
  i=$((i+1))
  log "[$i/$total] $s"

  # Pass variables safely; heredoc for the remote script avoids quoting pitfalls
  # shellcheck disable=SC2087
  status=$(ssh "root@$LXC_HOST" \
    "DRY_RUN=$DRY_RUN FORCE=$FORCE \
     SITES_DIR='$SITES_DIR' DOMAIN_SUFFIX='$DOMAIN_SUFFIX' \
     GITEA_HOST='$GITEA_HOST' GITEA_SSH_PORT='$GITEA_SSH_PORT' \
     GITEA_SSH_USER='$GITEA_SSH_USER' GITEA_REPO_OWNER='$GITEA_REPO_OWNER' \
     SITE_NAME='$s' bash -s" 2>>"$LOG" <<'INNER'
set -euo pipefail
SITE_DIR="$SITES_DIR/$SITE_NAME"
CFG="$SITE_DIR/site.json"

# ── Detect streamlit_app via Gitea probe (5s timeout) ──
streamlit_repo="${GITEA_REPO_OWNER}/streamlit-${SITE_NAME}"
streamlit_url="ssh://${GITEA_SSH_USER}@${GITEA_HOST}:${GITEA_SSH_PORT}/${streamlit_repo}.git"
if GIT_SSH_COMMAND="ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no" \
   git ls-remote --exit-code "$streamlit_url" 2>/dev/null | head -1 | grep -q .; then
  streamlit_value="\"streamlit-${SITE_NAME}\""
else
  streamlit_value="null"
fi

# ── Resolve version from git describe ──
version="v1.0.0"
if [[ -d "$SITE_DIR/.git" ]]; then
  git config --global --add safe.directory "$SITE_DIR" 2>/dev/null || true
  v=$(git -C "$SITE_DIR" describe --tags --exact-match 2>/dev/null || \
      git -C "$SITE_DIR" describe --tags --always 2>/dev/null || true)
  if [[ -n "$v" ]]; then version="$v"; fi
fi

domain="${SITE_NAME}${DOMAIN_SUFFIX}"

# Build the new document as a compact JSON string
new_doc=$(printf '{\n  "name": "%s",\n  "domain": "%s",\n  "published": true,\n  "version": "%s",\n  "streamlit_app": %s\n}\n' \
  "$SITE_NAME" "$domain" "$version" "$streamlit_value")

if [[ ! -f "$CFG" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "would-create"
  else
    echo "$new_doc" > "$CFG"
    chown "$(stat -c '%u:%g' "$SITE_DIR")" "$CFG" 2>/dev/null || true
    chmod 644 "$CFG"
    echo "created"
  fi
elif [[ "$FORCE" -eq 1 ]]; then
  # Merge: preserve existing keys; only fill missing ones from new_doc
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "would-merge"
  else
    merged=$(python3 - <<PYEOF
import json, sys
existing = json.loads(open('$CFG').read())
new = json.loads("""$new_doc""")
for k, v in new.items():
    existing.setdefault(k, v)
print(json.dumps(existing, indent=2))
PYEOF
)
    echo "$merged" > "$CFG"
    chmod 644 "$CFG"
    echo "merged"
  fi
else
  echo "skip-already-present"
fi
INNER
  )

  # Take only the last line as the machine-readable status token
  status=$(echo "$status" | tail -1 | tr -d '\r\n ')
  RESULT[$s]="$status"
  log "  -> $status"

  case "$status" in
    created|would-create)   count_created=$((count_created+1)) ;;
    merged|would-merge)     count_merged=$((count_merged+1)) ;;
    skip-*)                 count_skip=$((count_skip+1)) ;;
    *)                      count_fail=$((count_fail+1))
                            log "  FAIL: unexpected status '$status' for site '$s'" ;;
  esac
done

# ───── Write JSON report ─────
log "Writing $REPORT"
{
  printf '{\n'
  printf '  "date": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "dry_run": %s,\n' "$( [[ $DRY_RUN -eq 1 ]] && echo "true" || echo "false" )"
  printf '  "force": %s,\n' "$( [[ $FORCE -eq 1 ]] && echo "true" || echo "false" )"
  printf '  "total": %d,\n' "$total"
  printf '  "by_status": { "created": %d, "merged": %d, "skip": %d, "fail": %d },\n' \
    "$count_created" "$count_merged" "$count_skip" "$count_fail"
  printf '  "sites": {\n'
  first=1
  for s in "${sites[@]}"; do
    if [[ $first -eq 1 ]]; then first=0; else printf ',\n'; fi
    printf '    "%s": { "status": "%s" }' "$s" "${RESULT[$s]:-not-run}"
  done
  printf '\n  }\n'
  printf '}\n'
} > "$REPORT"

log "Summary: $total total, $count_created created, $count_merged merged, $count_skip skipped, $count_fail failed"
log "Report:  $REPORT"

[[ $count_fail -gt 0 ]] && exit 3 || exit 0
