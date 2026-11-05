#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Fait de ./release un lien vers /mnt quand /mnt a plus de place que le disque courant (#3480).
set -euo pipefail

libre() { df --output=avail -k "$1" | tail -1 | tr -d ' '; }

if [ -d /mnt ] && [ "$(libre /mnt)" -gt "$(libre .)" ]; then
  sudo install -d -o "$(id -u)" -g "$(id -g)" /mnt/release
  ln -sfn /mnt/release release
fi
mkdir -p release/
df -h . /mnt
