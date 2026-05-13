#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# scripts/metablog-webhook-uninstall.sh
# Remove the deploy webhook from every metablog-* repo on Gitea.
# Idempotent: skips repos with no matching hook.

set -euo pipefail

GITEA_URL="${GITEA_URL:-https://gitea.gk2.secubox.in}"
GITEA_TOKEN=""
WEBHOOK_URL="${WEBHOOK_URL:-https://admin.gk2.secubox.in/api/v1/metablogizer/webhook}"
OWNER="${OWNER:-gandalf}"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 --gitea-token <token> [options]

Required:
  --gitea-token <token>   Gitea admin or repo-admin API token

Options:
  --gitea-url   <url>     Gitea base URL (default: $GITEA_URL)
  --webhook-url <url>     Webhook URL to remove (default: $WEBHOOK_URL)
  --owner       <user>    Repo owner (default: $OWNER)
  --dry-run               List what would be removed; make no changes
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gitea-url)   GITEA_URL="$2"; shift 2 ;;
    --gitea-token) GITEA_TOKEN="$2"; shift 2 ;;
    --webhook-url) WEBHOOK_URL="$2"; shift 2 ;;
    --owner)       OWNER="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$GITEA_TOKEN" ]] || { echo "--gitea-token required" >&2; exit 2; }

API="$GITEA_URL/api/v1"
AUTH=(-H "Authorization: token $GITEA_TOKEN")

list_metablog_repos() {
  local page=1
  while :; do
    local body count
    body="$(curl -sS "${AUTH[@]}" "$API/users/$OWNER/repos?limit=50&page=$page")"
    count="$(echo "$body" | jq 'length')"
    [[ "$count" -gt 0 ]] || break
    echo "$body" | jq -r '.[] | select(.name | startswith("metablog-")) | .name'
    [[ "$count" -lt 50 ]] && break
    page=$((page + 1))
  done
}

removed=0; skipped=0; failed=0
mapfile -t REPOS < <(list_metablog_repos)
echo "found ${#REPOS[@]} metablog-* repos"

for repo in "${REPOS[@]}"; do
  hooks="$(curl -sS "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks")"
  id="$(echo "$hooks" | jq --arg url "$WEBHOOK_URL" 'map(select(.config.url == $url)) | first | .id // empty')"
  if [[ -z "$id" || "$id" == "null" ]]; then
    skipped=$((skipped + 1))
    printf "skip %s no-matching-hook\n" "$repo"
    continue
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    removed=$((removed + 1))
    printf "would remove: %s hook-id=%s\n" "$repo" "$id"
    continue
  fi
  code="$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE \
    "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks/$id")"
  if [[ "$code" == "204" ]]; then
    removed=$((removed + 1))
    printf "remove %s ok\n" "$repo"
  else
    failed=$((failed + 1))
    printf "remove %s FAIL http=%s\n" "$repo" "$code"
  fi
done

echo "summary: removed=$removed skipped=$skipped failed=$failed"
[[ $failed -eq 0 ]]
