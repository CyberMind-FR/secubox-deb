#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../../scripts/lib/test-helpers.sh
source "$REPO/scripts/lib/test-helpers.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo '["secubox-core","secubox-hub"]' > "$TMP/manifest.json"

output="$(bash "$REPO/scripts/build-packages.sh" bookworm amd64 --filter "$TMP/manifest.json" --dry-run 2>&1 || true)"

assert_contains "$output" "secubox-core"  "core should be in dry-run output"
assert_contains "$output" "secubox-hub"   "hub should be in dry-run output"

if [[ "$output" == *"secubox-crowdsec"* ]]; then
  echo "FAIL: crowdsec was NOT filtered out"
  echo "----- output -----"
  echo "$output"
  echo "------------------"
  exit 1
fi
pass "filter restricts package set"
