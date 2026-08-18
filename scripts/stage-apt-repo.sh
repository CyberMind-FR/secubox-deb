#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/stage-apt-repo.sh
# Stage a complete signed APT repo at output/repo/ for amd64 + arm64.
#
# Usage:
#   bash scripts/stage-apt-repo.sh [--tiers "base tier-lite tier-standard tier-pro"]
#                                  [--archs "arm64 amd64"]
#                                  [--suite bookworm]
#                                  [--out output/repo]
#                                  [--keep-going]
#
# Halt-on-tier-failure by default (lower tiers stay published).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
# shellcheck source=lib/tier-manifest.sh
source "$REPO/scripts/lib/tier-manifest.sh"

TIERS=(base tier-lite tier-standard tier-pro)
ARCHS=(arm64 amd64)
SUITE="bookworm"
OUT="$REPO/output/repo"
KEEP_GOING=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tiers)       IFS=' ' read -ra TIERS <<< "$2"; shift 2 ;;
    --archs)       IFS=' ' read -ra ARCHS <<< "$2"; shift 2 ;;
    --suite)       SUITE="$2"; shift 2 ;;
    --out)         OUT="$2"; shift 2 ;;
    --keep-going)  KEEP_GOING=1; shift ;;
    *)             echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

LOG="$REPO/output/build.log"
mkdir -p "$OUT" "$REPO/output/manifests" "$(dirname "$LOG")"
: > "$LOG"

log() { printf '[stage] %s\n' "$*" | tee -a "$LOG" >&2; }
fail() { printf '[stage] FAIL %s\n' "$*" | tee -a "$LOG" >&2; exit 1; }

# ───── 1. GPG bootstrap ─────
log "GPG bootstrap → $OUT"
bash "$REPO/scripts/stage-gpg-bootstrap.sh" "$OUT" >> "$LOG" 2>&1
FPR="$(cat "$OUT/FINGERPRINT.txt")"
[[ -z "$FPR" ]] && fail "fingerprint empty"
log "GPG fingerprint: $FPR"

# ───── 2. reprepro conf (production identity) ─────
log "Writing reprepro conf"
mkdir -p "$OUT/conf"
cat > "$OUT/conf/distributions" <<EOF
Origin: SecuBox
Label: SecuBox
Suite: $SUITE
Codename: $SUITE
Version: 12.0
Architectures: arm64 amd64 source
Components: main
Description: SecuBox Debian packages for Armada/x86_64
SignWith: $FPR
Contents: percomponent nocompatsymlink
EOF

cat > "$OUT/conf/options" <<EOF
verbose
basedir $OUT
gnupghome ${HOME}/.gnupg/secubox
EOF

# Initialize reprepro DB (idempotent — reprepro export creates dists/ if missing)
( cd "$OUT" && reprepro export "$SUITE" ) >> "$LOG" 2>&1 || fail "reprepro export failed"

# ───── 3. Tier loop ─────
declare -A TIER_RESULT
for tier in "${TIERS[@]}"; do
  log "────── Tier: $tier ──────"

  # 3a. Resolve manifest
  mf="$REPO/output/manifests/${tier}.json"
  if ! tier_manifest "$tier" "$mf"; then
    fail "tier-manifest failed for $tier"
  fi
  count="$(jq 'length' "$mf")"
  log "  packages: $count"

  tier_failed=0

  # 3b. Build per arch
  for arch in "${ARCHS[@]}"; do
    log "  build $tier × $arch"
    if ! bash "$REPO/scripts/build-packages.sh" "$SUITE" "$arch" --filter "$mf" >> "$LOG" 2>&1; then
      log "  build FAILED: $tier × $arch"
      tier_failed=1
      [[ $KEEP_GOING -eq 0 ]] && break
    fi
  done

  if [[ $tier_failed -eq 1 ]]; then
    TIER_RESULT[$tier]="FAILED"
    [[ $KEEP_GOING -eq 0 ]] && fail "tier $tier failed — halting (lower tiers remain published)"
    continue
  fi

  # 3c. Publish built debs that belong to this tier
  pkgs="$(jq -r '.[]' "$mf")"
  files=()
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    while IFS= read -r f; do
      [[ -n "$f" ]] && files+=("$f")
    done < <(ls "$REPO/output/debs/${p}_"*"_arm64.deb" \
                "$REPO/output/debs/${p}_"*"_amd64.deb" \
                "$REPO/output/debs/${p}_"*"_all.deb" 2>/dev/null || true)
  done <<< "$pkgs"

  if [[ ${#files[@]} -eq 0 ]]; then
    log "  no .debs to publish for tier $tier (skipping)"
    TIER_RESULT[$tier]="EMPTY"
    continue
  fi

  log "  publishing ${#files[@]} files"
  for f in "${files[@]}"; do
    ( cd "$OUT" && reprepro --silent includedeb "$SUITE" "$f" ) >> "$LOG" 2>&1 || {
      log "  publish FAILED: $f"
      [[ $KEEP_GOING -eq 0 ]] && fail "publish of $f failed in tier $tier"
    }
  done

  # 3d. Check after every tier
  log "  reprepro check"
  ( cd "$OUT" && reprepro check "$SUITE" ) >> "$LOG" 2>&1 || fail "reprepro check failed after tier $tier"

  TIER_RESULT[$tier]="OK"
done

# ───── 4. Manifest summary ─────
log "Writing MANIFEST.txt"
{
  echo "SecuBox APT Repo Staging — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Suite: $SUITE"
  echo "Fingerprint: $FPR"
  echo ""
  echo "Per-tier result:"
  for t in "${TIERS[@]}"; do
    printf "  %-20s %s\n" "$t" "${TIER_RESULT[$t]:-SKIPPED}"
  done
  echo ""
  echo "Per-arch package count:"
  for a in arm64 amd64 all; do
    n=$(find "$OUT/pool" -name "*_${a}.deb" 2>/dev/null | wc -l)
    printf "  %-6s %s\n" "$a" "$n"
  done
} > "$OUT/MANIFEST.txt"

log "Done. See $OUT/MANIFEST.txt"
