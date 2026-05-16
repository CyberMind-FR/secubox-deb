#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: Phase 2 Rspamd helpers (install + configure + dkim).
# Sourced library — do not execute directly.

# Re-entry guard — Phase 1 lesson. If a parent process re-sources this lib in
# a tight loop (e.g. through a deprecated shim that exec's back to mailctl)
# we will see SECUBOX_RSPAMD_SH_LOADED set and abort to break the recursion.
if [ "${_SECUBOX_RSPAMD_SH_LOADED:-0}" = "1" ]; then
    echo "rspamd.sh re-loaded — possible recursion, aborting" >&2
    return 1 2>/dev/null || exit 1
fi
export _SECUBOX_RSPAMD_SH_LOADED=1

# ─── install_rspamd ───────────────────────────────────────────────────────────
# Install Rspamd inside the named LXC. Idempotent — reruns are safe.
# Caller must ensure the LXC is RUNNING (we apt inside it).
install_rspamd() {
    local container="$1"
    [ -n "$container" ] || { echo "install_rspamd: container required" >&2; return 1; }
    if ! lxc-info -n "$container" 2>/dev/null | grep -q "State:.*RUNNING"; then
        echo "install_rspamd: LXC '$container' is not running" >&2
        return 1
    fi

    echo "[rspamd] installing inside LXC $container..."
    lxc-attach -n "$container" -- bash -c '
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        if dpkg -l rspamd 2>/dev/null | grep -q "^ii"; then
            echo "[rspamd] already installed"
            exit 0
        fi
        apt-get update -qq
        apt-get install -y --no-install-recommends rspamd redis-server
        # Redis is here as the future bayes/ratelimit backend; Phase 2 uses
        # sqlite defaults but having Redis installed means a Phase 8 switch
        # is config-only, not apt.
        systemctl disable redis-server.service 2>/dev/null || true
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    '
    echo "[rspamd] package installed in $container"
}
