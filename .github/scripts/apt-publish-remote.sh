#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: publication APT, côté serveur (#1036)
#
# Exécuté SUR la machine qui héberge le dépôt, via `ssh … bash -s < ce-fichier`.
#
# POURQUOI CE N'EST PAS UN `rsync` DU DÉPÔT. Le dépôt distant est géré par
# `reprepro`, base de données comprise. Un `rsync --delete` du côté runner
# écraserait cette base sans la connaître — et, parti d'un dépôt local vide,
# effacerait ce qui est publié. On dépose donc dans la zone de transit et on
# laisse reprepro faire son travail, exactement comme à la main.
#
# POURQUOI PAS `processincoming`. Il attend des `.changes`, que la chaîne de
# construction ne produit pas (paquets bâtis avec `-b`, non signés).
set -euo pipefail

BASE="${APT_BASE:-/data/apt}"
DIST="${APT_DIST:-bookworm}"
shopt -s nullglob

ok=0
refuses=()
for deb in "$BASE"/incoming/*.deb; do
    if reprepro -b "$BASE" includedeb "$DIST" "$deb"; then
        ok=$((ok + 1))
        rm -f "$deb"
    else
        # UN REFUS ISOLÉ EST LE CAS ORDINAIRE : republier un tag réimporte des
        # versions déjà présentes. On le nomme, on le garde en transit pour
        # inspection, et on continue.
        refuses+=("$(basename "$deb")")
    fi
done

echo "importés: $ok — refusés: ${#refuses[@]}"
for r in "${refuses[@]}"; do
    echo "  refusé: $r"
done

# ZÉRO IMPORT EST UNE ERREUR, pas un silence. C'est le seul cas qui signale que
# la publication n'a rien produit — sans quoi le workflow rendrait vert sur un
# dépôt inchangé, ce qui est précisément le défaut qu'on corrige.
if [ "$ok" -eq 0 ]; then
    echo "aucun paquet importé — la publication n'a rien changé" >&2
    exit 1
fi
