#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════
# SecuBox — run-vbox.sh  (SUPERSEDED / OBSOLÈTE)
#
# Ce script est remplacé par le script VirtualBox canonique :
#     image/create-vbox-vm.sh
# Il n'est conservé que comme redirection rétro-compatible. Ses options
# (-n/--name, -m/--memory, -c/--cpus, -s/--ssh, -w/--https, --delete) sont
# un sous-ensemble de celles du canonique ; --delete devient --force.
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANON="$(dirname "$SCRIPT_DIR")/image/create-vbox-vm.sh"

echo "[run-vbox] OBSOLÈTE — utilise: image/create-vbox-vm.sh" >&2

# --delete (ancien) → --force (canonique) ; le reste est identique.
args=()
for a in "$@"; do
    case "$a" in
        --delete) args+=(--force) ;;
        *)        args+=("$a") ;;
    esac
done
exec "$CANON" "${args[@]}"
