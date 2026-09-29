#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: empreinte-front — sha256 des sources d'un front (#1611) :
# lockfile, configs, sdk, app, outils. Même entrée → même empreinte.
set -euo pipefail
cd "${1:?usage : empreinte-front.sh <paquet>}"
# + les fichiers d'autres paquets qu'Aurora importe au build (#1656).
find package.json package-lock.json .nvmrc app sbx-sdk outils \
     ../secubox-voice/conf/commandes.json ../secubox-radio/capabilities.d/radio.json -type f -print0 \
  | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
