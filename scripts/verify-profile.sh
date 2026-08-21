#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# verify-profile.sh <isp|full> — porte « propre » (#1112).
#
# Refuse un profil dont UN module référencé (chaîne Depends, méta-paquets
# résolus récursivement) n'existe pas comme paquet buildable OU n'est pas dans
# le working-set du board de référence (services enabled + catalogue all.gk2).
# Un module non fini / désactivé ne peut donc pas entrer dans une image.
set -euo pipefail
PROFILE="${1:?usage: verify-profile.sh <isp|full>}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CTRL="$REPO/packages/secubox-${PROFILE}/debian/control"
WS="${WORKING_SET:-$REPO/image/profiles/working-set.gk2.txt}"
[[ -f "$CTRL" ]] || { echo "profil inconnu : secubox-$PROFILE ($CTRL absent)"; exit 2; }
[[ -f "$WS"   ]] || { echo "working-set absent : $WS"; exit 2; }

mapfile -t WORKING < <(grep -vE '^\s*#|^\s*$' "$WS")
in_ws(){ local x; for x in "${WORKING[@]}"; do [[ "$x" == "$1" ]] && return 0; done; return 1; }
deps_of(){ awk '/^Depends:/{f=1} f&&/^[A-Z][a-zA-Z-]*:/&&!/^Depends:/{f=0} f' "$1" | grep -oE 'secubox-[a-z0-9-]+' | sed 's/secubox-//' | sort -u; }
is_meta(){ grep -q '^Section: metapackages' "$1" 2>/dev/null; }

FAIL=0; declare -A SEEN
check(){
  local m="$1"; [[ -n "${SEEN[$m]:-}" ]] && return; SEEN[$m]=1
  local c="$REPO/packages/secubox-$m/debian/control"
  if [[ ! -f "$c" ]]; then echo "  ✗ $m : aucun paquet packages/secubox-$m"; FAIL=1; return; fi
  if is_meta "$c"; then local s; while read -r s; do [[ -n "$s" ]] && check "$s"; done < <(deps_of "$c"); return; fi
  in_ws "$m" || { echo "  ✗ $m : hors working-set (ni service enabled ni catalogue all.gk2)"; FAIL=1; }
}
m=""; while read -r m; do [[ -n "$m" ]] && check "$m"; done < <(deps_of "$CTRL")
if [[ $FAIL -eq 0 ]]; then
  echo "✓ profil secubox-$PROFILE : $(printf '%s\n' "${!SEEN[@]}" | wc -l) modules, tous buildables et working"
else
  echo "✗ profil secubox-$PROFILE INVALIDE — corrige la chaîne Depends ou régénère le working-set"; exit 1
fi
