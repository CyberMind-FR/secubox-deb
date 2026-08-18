#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/validate-staged-repo.sh
# Validate output/repo/ end-to-end.
#   1. reprepro check
#   2. gpg --verify on InRelease
#   3. license files match project root byte-for-byte
#   4. (best-effort) chroot apt-get update against file:// URL
#
# Usage: bash scripts/validate-staged-repo.sh [<out_dir>]
#   SKIP_CHROOT=1 to skip step 4 (e.g., on CI without sudo).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
OUT="${1:-$REPO/output/repo}"
SUITE="${SUITE:-bookworm}"

log() { echo "[validate] $*"; }
fail() { echo "[validate] FAIL: $*" >&2; exit 1; }

# 1. reprepro check
log "reprepro check"
( cd "$OUT" && reprepro check "$SUITE" ) || fail "reprepro check failed"

# 2. gpg verify
log "gpg --verify InRelease"
if ! gpg --homedir "$HOME/.gnupg/secubox" --verify "$OUT/dists/$SUITE/InRelease" 2>&1 \
     | grep -qE "Good signature|Bonne signature"; then
  fail "InRelease signature did not verify"
fi

# 3. License sanity
log "license byte-match"
cmp "$REPO/LICENCE-CMSD-1.0.md"    "$OUT/LICENCE-CMSD-1.0.md"    || fail "French license differs from project root"
cmp "$REPO/LICENSE-CMSD-1.0.en.md" "$OUT/LICENSE-CMSD-1.0.en.md" || fail "English license differs from project root"

# 4. chroot apt-get update (best-effort)
CHROOT="$REPO/output/test-chroot"
if [[ -z "${SKIP_CHROOT:-}" ]]; then
  log "chroot apt update (best-effort)"
  if ! command -v debootstrap >/dev/null; then
    log "  debootstrap missing — skipping chroot test (set SKIP_CHROOT=1 to silence)"
  else
    sudo rm -rf "$CHROOT"
    if ! sudo debootstrap --variant=minbase "$SUITE" "$CHROOT" http://deb.debian.org/debian/ >/dev/null 2>&1; then
      log "  debootstrap failed (network?) — skipping chroot test"
    else
      sudo install -d -m 0755 "$CHROOT/etc/apt/sources.list.d" "$CHROOT/usr/share/keyrings"
      # dearmor: apt signed-by= needs a binary keyring, not the ASCII-armored export
      gpg --dearmor < "$OUT/secubox-keyring.gpg" | sudo tee "$CHROOT/usr/share/keyrings/secubox.gpg" >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/secubox.gpg] file://$OUT $SUITE main" \
        | sudo tee "$CHROOT/etc/apt/sources.list.d/secubox.list" >/dev/null
      sudo mkdir -p "$CHROOT$OUT"
      sudo mount --bind "$OUT" "$CHROOT$OUT"
      # Capture log first; check separately so pipefail on apt-get's exit
      # status (it may warn about file:// or unsigned packages) doesn't mask
      # a successful repo-discovery check.
      sudo chroot "$CHROOT" apt-get update 2>&1 | tee "$REPO/output/chroot-update.log" >/dev/null || true
      sudo umount "$CHROOT$OUT"
      if ! grep -qE "Get.*$SUITE|file:.*$SUITE" "$REPO/output/chroot-update.log"; then
        fail "chroot apt-get update did not see SecuBox repo (see output/chroot-update.log)"
      fi
      log "  chroot apt-get update OK"
    fi
  fi
else
  log "chroot test skipped (SKIP_CHROOT set)"
fi

log "All validation checks passed"
