#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox Eye Remote — USB OTG disconnect handler.
# Called by udev when a Pi RNDIS gadget is unplugged. The slave netdev is
# already gone by the time udev fires the remove event, so this script only
# notifies the API and logs.

set -euo pipefail

IFACE="${INTERFACE:-${1:-}}"

log() { logger -t "secubox-eye-remote" "$*"; }

log "Eye Remote disconnect: ${IFACE:-<unknown>}"

if command -v curl >/dev/null 2>&1; then
    curl --max-time 2 -s -X POST \
        "http://127.0.0.1:8000/api/v1/system/eye-remote/disconnected" \
        -H "Content-Type: application/json" \
        -d "{\"interface\": \"${IFACE:-}\"}" \
        >/dev/null 2>&1 || true
fi
