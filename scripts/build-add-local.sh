#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Builder un package et l'ajouter au repo local
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

PKG="${1:-}"
SUITE="${2:-bookworm}"
ARCH="${3:-$(dpkg --print-architecture)}"

[[ -z "$PKG" ]] && { echo "Usage: $0 <package-name> [suite] [arch]"; exit 1; }

PKG_DIR="${REPO_DIR}/packages/${PKG}"
[[ -d "$PKG_DIR" ]] || { echo "Package not found: $PKG_DIR"; exit 1; }

cd "$PKG_DIR"

if [[ "$ARCH" == "arm64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
  dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b
else
  dpkg-buildpackage -us -uc -b
fi

# Find generated .deb
cd "${REPO_DIR}/packages"
DEB=$(ls -t ${PKG}_*.deb 2>/dev/null | head -1)
[[ -n "$DEB" ]] && bash "${SCRIPT_DIR}/local-repo-add.sh" "$SUITE" "$DEB"
