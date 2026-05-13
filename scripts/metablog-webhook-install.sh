#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# scripts/metablog-webhook-install.sh
# Register the deploy webhook on every metablog-* repo on Gitea.
# Idempotent: skips repos that already have a hook with the target URL.

set -euo pipefail

GITEA_URL="${GITEA_URL:-https://gitea.gk2.secubox.in}"
GITEA_TOKEN=""
WEBHOOK_URL="${WEBHOOK_URL:-https://admin.gk2.secubox.in/api/v1/metablogizer/webhook}"
SECRET_FILE=""
OWNER="${OWNER:-gandalf}"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 --gitea-token <token> --secret-file <path> [options]

Required:
  --gitea-token <token>   Gitea admin or repo-admin API token
  --secret-file <path>    File containing the HMAC shared secret (or "-" for stdin)

Options:
  --gitea-url   <url>     Gitea base URL (default: $GITEA_URL)
  --webhook-url <url>     Webhook target URL (default: $WEBHOOK_URL)
  --owner       <user>    Repo owner (default: $OWNER)
  --dry-run               List what would be done; make no changes
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gitea-url)   GITEA_URL="$2"; shift 2 ;;
    --gitea-token) GITEA_TOKEN="$2"; shift 2 ;;
    --webhook-url) WEBHOOK_URL="$2"; shift 2 ;;
    --secret-file) SECRET_FILE="$2"; shift 2 ;;
    --owner)       OWNER="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$GITEA_TOKEN" ]] || { echo "--gitea-token required" >&2; exit 2; }
[[ -n "$SECRET_FILE" ]] || { echo "--secret-file required" >&2; exit 2; }

if [[ "$SECRET_FILE" == "-" ]]; then
  SECRET="$(cat)"
else
  [[ -r "$SECRET_FILE" ]] || { echo "secret file not readable: $SECRET_FILE" >&2; exit 2; }
  SECRET="$(cat "$SECRET_FILE")"
fi
SECRET="${SECRET//$'\n'/}"   # strip newlines
[[ -n "$SECRET" ]] || { echo "secret is empty" >&2; exit 2; }

API="$GITEA_URL/api/v1"
AUTH=(-H "Authorization: token $GITEA_TOKEN")
JSON=(-H "Content-Type: application/json")

# Page through all repos for OWNER, collect metablog-* names.
list_metablog_repos() {
  local page=1
  while :; do
    local body
    body="$(curl -sS "${AUTH[@]}" "$API/users/$OWNER/repos?limit=50&page=$page")"
    # If the response is empty array we stop.
    local count
    count="$(echo "$body" | jq 'length')"
    [[ "$count" -gt 0 ]] || break
    echo "$body" | jq -r '.[] | select(.name | startswith("metablog-")) | .name'
    [[ "$count" -lt 50 ]] && break
    page=$((page + 1))
  done
}

repo_has_hook() {
  local repo="$1"
  curl -sS "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks" \
    | jq -e --arg url "$WEBHOOK_URL" 'any(.[]; .config.url == $url)' >/dev/null
}

install_hook() {
  local repo="$1"
  local payload
  payload="$(jq -n --arg url "$WEBHOOK_URL" --arg secret "$SECRET" '{
    type: "gitea",
    config: { url: $url, content_type: "json", secret: $secret },
    events: ["push"],
    active: true
  }')"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "would install: $repo"
    return 0
  fi
  curl -sS -o /dev/null -w "%{http_code}" \
    "${AUTH[@]}" "${JSON[@]}" \
    -X POST -d "$payload" \
    "$API/repos/$OWNER/$repo/hooks"
}

installed=0; skipped=0; failed=0
mapfile -t REPOS < <(list_metablog_repos)
echo "found ${#REPOS[@]} metablog-* repos"

for repo in "${REPOS[@]}"; do
  if repo_has_hook "$repo"; then
    skipped=$((skipped + 1))
    printf "skip %s already-hooked\n" "$repo"
    continue
  fi
  code="$(install_hook "$repo" 2>/dev/null || echo "000")"
  if [[ $DRY_RUN -eq 1 ]]; then
    installed=$((installed + 1))
  elif [[ "$code" == "201" ]]; then
    installed=$((installed + 1))
    printf "install %s ok\n" "$repo"
  else
    failed=$((failed + 1))
    printf "install %s FAIL http=%s\n" "$repo" "$code"
  fi
done

echo "summary: installed=$installed skipped=$skipped failed=$failed"
[[ $failed -eq 0 ]]
