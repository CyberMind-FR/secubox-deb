#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox — create-secubox-vm.sh  (SUPERSEDED / OBSOLÈTE)
#
# Remplacé par le script VirtualBox canonique : image/create-vbox-vm.sh
# Conservé comme redirection rétro-compatible. Traduit les anciennes
# options --ssh-port/--https-port vers --ssh/--https.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANON="$(dirname "$SCRIPT_DIR")/image/create-vbox-vm.sh"

echo "[create-secubox-vm] OBSOLÈTE — utilise: image/create-vbox-vm.sh" >&2

args=()
for a in "$@"; do
    case "$a" in
        --ssh-port)   args+=(--ssh) ;;
        --https-port) args+=(--https) ;;
        *)            args+=("$a") ;;
    esac
done
exec "$CANON" "${args[@]}"
