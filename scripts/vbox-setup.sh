#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox — vbox-setup.sh  (SUPERSEDED / OBSOLÈTE)
#
# Remplacé par le script VirtualBox canonique : image/create-vbox-vm.sh
# Conservé comme redirection rétro-compatible. Ce script téléchargeait puis
# configurait la VM : par défaut on force donc --download. Le mode réseau
# « bridged » n'est pas repris (le canonique fait du NAT + redirection de
# ports, plus simple et sans dépendance à un adaptateur hôte).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANON="$(dirname "$SCRIPT_DIR")/image/create-vbox-vm.sh"

echo "[vbox-setup] OBSOLÈTE — utilise: image/create-vbox-vm.sh --download" >&2

args=()
has_image=0 has_download=0
skip_next=0
for a in "$@"; do
    if [[ "$skip_next" -eq 1 ]]; then skip_next=0; continue; fi
    case "$a" in
        --memory)     args+=(-m) ;;
        --cpus)       args+=(-c) ;;
        --download)   has_download=1; args+=(--download) ;;
        --network)    echo "[vbox-setup] --network ignoré (NAT uniquement)" >&2; skip_next=1 ;;
        --bridge)     echo "[vbox-setup] --bridge ignoré (NAT uniquement)"  >&2; skip_next=1 ;;
        -*)           args+=("$a") ;;
        *)            [[ -f "$a" ]] && has_image=1; args+=("$a") ;;
    esac
done
# Ce script servait à télécharger+lancer : sans image ni --download, on télécharge.
[[ "$has_image" -eq 0 && "$has_download" -eq 0 ]] && args=(--download "${args[@]}")

exec "$CANON" "${args[@]}"
