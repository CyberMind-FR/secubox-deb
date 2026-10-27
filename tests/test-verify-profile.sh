#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Test de la porte verify-profile (#1112).
set -euo pipefail
cd "$(dirname "$0")/.."
# 1) les QUATRE profils réels passent (minimal manquait : alpha.19, deux images refusées sur « courbes », #3208)
for prof in minimal lite isp full; do
  bash scripts/verify-profile.sh "$prof" >/dev/null || { echo "FAIL: $prof devrait passer"; exit 1; }
done
# 2) working-set amputé d'un module dont le profil dépend → profil REFUSÉ (preuve que la porte mord).
#    'waf' ne prouvait plus rien : isp n'en dépend plus. modem (isp) et courbes (minimal) sont des dépendances directes.
refuse() {  # refuse <profil> <module retiré>
  local tmp; tmp="$(mktemp)"; grep -vx "$2" image/profiles/working-set.gk2.txt > "$tmp"
  if WORKING_SET="$tmp" bash scripts/verify-profile.sh "$1" >/dev/null 2>&1; then
    echo "FAIL: $1 aurait dû être refusé ($2 retiré du working-set)"; rm -f "$tmp"; exit 1
  fi
  rm -f "$tmp"
}
refuse isp modem
refuse minimal courbes
echo "OK: verify-profile — profils valides acceptés, module hors working-set refusé"
