#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Test de la porte verify-profile (#1112).
set -euo pipefail
cd "$(dirname "$0")/.."
# 1) les deux profils réels passent
bash scripts/verify-profile.sh isp  >/dev/null || { echo "FAIL: isp devrait passer"; exit 1; }
bash scripts/verify-profile.sh full >/dev/null || { echo "FAIL: full devrait passer"; exit 1; }
# 2) working-set amputé de 'waf' → isp DOIT être refusé (preuve que la porte mord)
tmp="$(mktemp)"; grep -vx waf image/profiles/working-set.gk2.txt > "$tmp"
if WORKING_SET="$tmp" bash scripts/verify-profile.sh isp >/dev/null 2>&1; then
  echo "FAIL: isp aurait dû être refusé (waf retiré du working-set)"; rm -f "$tmp"; exit 1
fi
rm -f "$tmp"
echo "OK: verify-profile — profils valides acceptés, module hors working-set refusé"
