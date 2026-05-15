#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: Phase 1 defensive migration detectors.
# Sourced library — do not execute directly.

# Detect legacy two-LXC layout under $LXC_BASE. Echoes any legacy
# container names found, one per line. Returns 0 if any, 1 if none.
detect_legacy_lxc() {
    local base="${LXC_BASE:-/var/lib/lxc}"
    local found=0
    local c
    for c in mailserver roundcube; do
        if [ -d "$base/$c/rootfs" ]; then
            echo "$c"
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

# Refuse to touch the data dir if /vmail has any nested content. This
# enforces spec rev. 2 invariant I13 (existing mail data must be preserved).
# Returns 0 if safe to clobber; non-zero with explanation otherwise.
guard_data_path() {
    local data="${DATA_PATH:-/data/volumes/mail}"
    if [ ! -d "$data/vmail" ]; then
        return 0
    fi
    local count
    count=$(find "$data/vmail" -mindepth 2 -print -quit 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "ERROR: $data/vmail already has data — refusing to touch (invariant I13)" >&2
        return 1
    fi
    return 0
}

# Echo any legacy keys present in a mail.toml file (one per line).
# Returns 0 if any legacy key is present, 1 if the file is already migrated.
detect_legacy_toml_keys() {
    local toml="$1"
    [ -f "$toml" ] || return 1
    local found=0
    local k
    for k in mail_container webmail_container mail_ip webmail_ip webmail_port; do
        if grep -q "^${k} *=" "$toml" 2>/dev/null; then
            echo "$k"
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
