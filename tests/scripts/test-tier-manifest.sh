#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"
source "$REPO/scripts/lib/tier-manifest.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# base = hardcoded
tier_manifest "base" "$TMP/base.json"
assert_file "$TMP/base.json" "base manifest"
got="$(jq -r '. | sort | .[]' "$TMP/base.json" | tr '\n' ' ')"
assert_eq "secubox-core secubox-hub " "$got" "base packages"

# tier-lite must produce a manifest with >=3 packages and include secubox-core (via inheritance)
tier_manifest "tier-lite" "$TMP/lite.json"
assert_file "$TMP/lite.json" "lite manifest"
count="$(jq 'length' "$TMP/lite.json")"
if [[ "$count" -lt 3 ]]; then
  echo "FAIL: tier-lite has only $count packages, expected >=3"
  cat "$TMP/lite.json"
  exit 1
fi
if ! jq -e '. | index("secubox-core")' "$TMP/lite.json" >/dev/null; then
  echo "FAIL: tier-lite missing secubox-core (inheritance broken)"
  exit 1
fi

pass "tier-manifest base + tier-lite"
