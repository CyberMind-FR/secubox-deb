#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox ToolBoX Cartographie — build the unsigned .xpi (a zip of the
# extension dir). Firefox loads it as-is (temporary add-on / ESR with
# signatures off) ; a release build signs it via web-ext / AMO.
# Usage: ./build.sh   → produces ./secubox-toolbox-webext-<version>.xpi
set -euo pipefail
cd "$(dirname "$0")"

VER=$(grep -oE '"version"[^,]*' manifest.json | grep -oE '[0-9.]+' | head -1)
OUT="secubox-toolbox-webext-${VER}.xpi"
rm -f "$OUT"

# -FS = sync (drop stale entries) ; exclude VCS, dotfiles, build script,
# any previously built artefact, and docs.
zip -r -FS "$OUT" . \
  -x '*.git*' '*/.*' 'build.sh' '*.xpi' 'README.md' >/dev/null

echo "built $OUT ($(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT") bytes)"
echo "Firefox: about:debugging → This Firefox → Load Temporary Add-on → pick the .xpi (or manifest.json)."
echo "Permanent install needs signing (web-ext sign / AMO) or Dev/ESR with xpinstall.signatures.required=false."
echo "Chromium: action icons must be raster — rasterise icons/icon.svg to PNG before a Chromium store build."
