#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# snapshot-working-set.sh <root@board> — régénère image/profiles/working-set.gk2.txt
# (services secubox-* enabled + apps LXC du catalogue all.gk2). #1112.
set -euo pipefail
BOARD="${1:?usage: snapshot-working-set.sh root@board}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/image/profiles/working-set.gk2.txt"
{
  echo "# Working-set SecuBox — snapshot de ${BOARD} ($(date -u +%F))."
  echo "# Services systemd secubox-* enabled. Source de vérité pour verify-profile.sh."
  ssh "$BOARD" "systemctl list-unit-files 'secubox-*.service' --state=enabled --no-legend" \
    | awk '{print $1}' | sed 's/secubox-//; s/\.service//' | sort -u
  echo "defaults"
  echo "# --- apps LXC-native du catalogue all.gk2 (pas de service hôte enabled) ---"
  ssh "$BOARD" "grep -oE '[a-z0-9-]+\.gk2\.secubox\.in' /srv/metablogizer/sites/all/public/index.html 2>/dev/null" \
    | sed -E 's/\.gk2\.secubox\.in//; s/^cloud$/nextcloud/' | grep -vE '^(www|)$' | sort -u
} > "$OUT"
echo "→ régénéré : $OUT"
