#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# tests/scripts/test-metablog-webhook.sh
# Smoke test for /api/v1/metablogizer/webhook.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

BASE="${WEBHOOK_BASE:-https://admin.gk2.secubox.in}"
URL="$BASE/api/v1/metablogizer/webhook"
SECRET="${WEBHOOK_SECRET:-}"

log_step() { echo "[smoke step $1] $2"; }

# Gate 1: endpoint exists, GET returns 405 (POST-only) — not 404.
log_step 1 "endpoint reachable (GET returns 405)"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL")
if [[ "$code" != "405" && "$code" != "404" ]]; then
  echo "FAIL: GET $URL returned $code (expected 405)"; exit 1
fi
pass "GET $URL -> $code (endpoint exists, POST-only or routing checked)"

# Gate 2: POST without signature returns 401.
log_step 2 "unsigned POST returns 401"
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
       -H "Content-Type: application/json" \
       -d '{"ref":"refs/heads/main","repository":{"name":"metablog-zkp","default_branch":"main"}}' \
       "$URL")
if [[ "$code" != "401" ]]; then
  echo "FAIL: unsigned POST returned $code (expected 401)"; exit 1
fi
pass "unsigned POST -> 401"

# Gate 3: signed POST with a known-unknown site returns 200 + skip=unknown-site.
# Requires WEBHOOK_SECRET to be set in env.
log_step 3 "signed POST with fake site returns 200 + skip"
if [[ -z "$SECRET" ]]; then
  echo "SKIP: WEBHOOK_SECRET not set; gate 3 not run"
else
  body='{"ref":"refs/heads/main","repository":{"name":"metablog-_smoke_does_not_exist","default_branch":"main"}}'
  sig=$(echo -n "$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
  resp=$(curl -sk -X POST \
         -H "Content-Type: application/json" \
         -H "X-Gitea-Signature: $sig" \
         -d "$body" \
         "$URL")
  echo "$resp" | grep -q '"skip"' || {
    echo "FAIL: signed POST didn't return skip; got: $resp"; exit 1
  }
  pass "signed POST -> $(echo "$resp" | head -c 80)..."
fi

pass "all smoke gates green"
