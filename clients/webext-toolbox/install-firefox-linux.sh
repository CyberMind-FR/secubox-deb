#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox ToolBoX — Linux Firefox installer (#547)
# One call: grab the ToolBoX cartographie extension and launch Firefox with
# it loaded. Prefers `web-ext run` (temporary load, works unsigned — fastest)
# and falls back to opening the .xpi for the install prompt.
#
# Usage:
#   ./install-firefox-linux.sh                 # from kbin.gk2.secubox.in
#   ./install-firefox-linux.sh kbin.my.box     # from another cabine host
#   ./install-firefox-linux.sh --release       # from the latest GitHub release
#   ./install-firefox-linux.sh --local         # build from this checkout (web-ext)
set -euo pipefail

DEFAULT_HOST="kbin.gk2.secubox.in"
RELEASE_URL="https://github.com/CyberMind-FR/secubox-deb/releases/download/webext-v0.1.4/secubox-toolbox-webext.xpi"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

say(){ printf '\033[1;36m▸\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die(){ printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ── resolve source ──
MODE="host"; HOST="$DEFAULT_HOST"; SRC_URL=""
case "${1:-}" in
  --release) MODE="release"; SRC_URL="$RELEASE_URL" ;;
  --local)   MODE="local" ;;
  "")        SRC_URL="https://${HOST}/wg/toolbox.xpi" ;;
  -*)        die "unknown flag: $1 (use --release | --local | <host>)" ;;
  *)         HOST="$1"; SRC_URL="https://${HOST}/wg/toolbox.xpi" ;;
esac

# ── find a Firefox binary ──
FX=""
for c in firefox firefox-esr firefox-bin firefox-developer-edition; do
  if command -v "$c" >/dev/null 2>&1; then FX="$c"; break; fi
done
if [ -z "$FX" ] && command -v flatpak >/dev/null 2>&1 \
   && flatpak info org.mozilla.firefox >/dev/null 2>&1; then
  FX="flatpak run org.mozilla.firefox"
fi
[ -n "$FX" ] || die "no Firefox found (install firefox / firefox-esr, or flatpak org.mozilla.firefox)"
say "Firefox: $FX"

have_webext(){ command -v web-ext >/dev/null 2>&1 || command -v npx >/dev/null 2>&1; }
runwebext(){ if command -v web-ext >/dev/null 2>&1; then web-ext "$@"; else npx --yes web-ext "$@"; fi; }

# ── fastest path: web-ext run (temporary load, no signing needed) ──
if have_webext; then
  SRCDIR=""
  if [ "$MODE" = "local" ]; then
    [ -f "$SELF_DIR/manifest.json" ] || die "--local: no manifest.json next to this script"
    SRCDIR="$SELF_DIR"
  else
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    say "Downloading extension from ${SRC_URL} …"
    curl -fsSL "$SRC_URL" -o "$TMP/sbx.xpi" || die "download failed: $SRC_URL"
    head -c2 "$TMP/sbx.xpi" | grep -q PK || die "not a valid .xpi (zip) — wrong host/URL?"
    mkdir -p "$TMP/ext" && ( cd "$TMP/ext" && unzip -q "$TMP/sbx.xpi" )
    SRCDIR="$TMP/ext"
  fi
  say "Launching Firefox with the ToolBoX extension loaded (temporary)…"
  FXBIN="${FX%% *}"   # web-ext wants the binary, not a flatpak wrapper
  if [ "$FX" = "${FX# }" ] && command -v "$FXBIN" >/dev/null 2>&1; then
    exec runwebext run --source-dir "$SRCDIR" --firefox "$FXBIN" \
        --start-url "https://${HOST}/social/me"
  fi
  exec runwebext run --source-dir "$SRCDIR" --start-url "https://${HOST}/social/me"
fi

# ── fallback: open the .xpi so Firefox shows the install prompt ──
warn "web-ext not found (no npx) — falling back to the install prompt."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
[ "$MODE" = "local" ] && die "--local needs web-ext/npx; install nodejs or use a host/--release"
say "Downloading ${SRC_URL} …"
curl -fsSL "$SRC_URL" -o "$TMP/secubox-toolbox-webext.xpi" || die "download failed"
head -c2 "$TMP/secubox-toolbox-webext.xpi" | grep -q PK || die "not a valid .xpi"
cat <<'NOTE'
! The .xpi is unsigned. Stock Firefox release refuses a permanent install.
  Use Firefox ESR/Developer/Nightly, or set in about:config:
      xpinstall.signatures.required = false
  …then accept the install prompt that opens now.
NOTE
say "Opening Firefox on the extension…"
exec $FX "$TMP/secubox-toolbox-webext.xpi"
