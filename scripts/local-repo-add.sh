#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Ajouter un .deb au repo local
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LOCAL_REPO="${REPO_DIR}/cache/repo"

SUITE="${1:-bookworm}"
shift || true

for DEB in "$@"; do
  [[ -f "$DEB" ]] || { echo "SKIP: $DEB (not found)"; continue; }
  reprepro -b "${LOCAL_REPO}" includedeb "${SUITE}" "$DEB"
  echo "OK: Added $(basename "$DEB") to ${SUITE}"
done
