#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox Companion — build the unsigned .xpi (a zip of the extension dir).
# Usage: ./build.sh   → produces ../secubox-webext-<version>.xpi
set -euo pipefail
cd "$(dirname "$0")"
VER=$(grep -oE '"version"[^,]*' manifest.json | grep -oE '[0-9.]+' | head -1)
OUT="../secubox-webext-${VER}.xpi"
rm -f "$OUT"
# -FS = sync (delete stale entries); exclude VCS + dotfiles + the build script.
zip -r -FS "$OUT" . -x '*.git*' '*/.*' 'build.sh' >/dev/null
echo "built $OUT"
echo "Load in Firefox: about:debugging → This Firefox → Load Temporary Add-on → pick this .xpi (or manifest.json)."
echo "Permanent install requires signing (web-ext sign / AMO) or Developer/ESR with xpinstall.signatures.required=false."
