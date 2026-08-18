#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/scripts/test-gitea-routing.sh
# Validates the 5 gates from docs/superpowers/specs/2026-05-12-gitea-repair-design.md.
# Run from the repo root or anywhere — uses absolute test-helper path.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../../scripts/lib/test-helpers.sh
source "$REPO/scripts/lib/test-helpers.sh"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"

log_step() { echo "[gate $1] $2"; }

# Gate 1: HTTPS reachability + HTTP 200
log_step 1 "HTTPS GET /"
code=$(curl -s -o /dev/null -w "%{http_code}" "https://$GITEA_HOST/")
assert_eq "200" "$code" "Gitea web HTTPS code"

# Gate 2: TLS cert SAN includes the wildcard
log_step 2 "TLS SAN check"
san=$(echo | openssl s_client -servername "$GITEA_HOST" -connect "$GITEA_HOST:443" 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName 2>&1)
assert_contains "$san" "*.gk2.secubox.in" "wildcard SAN covers $GITEA_HOST"

# Gate 3: Response body is a Gitea page (contains <title>)
log_step 3 "HTML body sanity"
body=$(curl -s "https://$GITEA_HOST/")
assert_contains "$body" "<title>" "response is HTML with a <title>"

# Gate 4: SSH on 2222 — TCP path open, SSH server responds
log_step 4 "SSH protocol reachability on port $GITEA_SSH_PORT"
ssh_out=$(ssh -p "$GITEA_SSH_PORT" -o ConnectTimeout=5 -o BatchMode=yes \
              -o StrictHostKeyChecking=accept-new \
              "git@$GITEA_HOST" 2>&1 | head -3 || true)
if echo "$ssh_out" | grep -qE "Permission denied|successfully authenticated|Hi there"; then
  pass "SSH server responded on port $GITEA_SSH_PORT"
else
  echo "FAIL: gate 4 — SSH did not respond properly"
  echo "----- ssh output -----"
  echo "$ssh_out"
  echo "----------------------"
  exit 1
fi

# Gate 5: round-trip git over HTTPS (skipped if no GITEA_TOKEN env var)
log_step 5 "HTTPS git round-trip (optional)"
if [[ -z "${GITEA_TOKEN:-}" || -z "${GITEA_USER:-}" || -z "${GITEA_TEST_REPO:-}" ]]; then
  log_step 5 "SKIP — GITEA_TOKEN / GITEA_USER / GITEA_TEST_REPO not set"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  clone_url="https://${GITEA_USER}:${GITEA_TOKEN}@${GITEA_HOST}/${GITEA_USER}/${GITEA_TEST_REPO}.git"
  if git clone --depth 1 "$clone_url" "$tmp/repo" >/dev/null 2>&1; then
    pass "git clone over HTTPS"
  else
    echo "FAIL: gate 5 — git clone over HTTPS failed"
    exit 1
  fi
fi

pass "all gates passed"
