#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Phase 1 rev. 2 migration scanner. Defensive — does NOT create or destroy
# anything by default. Reports legacy state and exits 0 even if legacy
# fragments are found, so debian/postinst can call us without aborting
# the upgrade. Per spec invariant I13, existing /data/volumes/mail/vmail
# data is sacrosanct and never touched.
#
# Invoked from secubox-mail debian/postinst on upgrade from < 2.2.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="${LIB_DIR:-/usr/lib/secubox/mail/lib}"
# Installed layout flattens lib/mail/*.sh → /usr/lib/secubox/mail/lib/*.sh.
# In-tree fallback keeps the lib/mail/ subdir.
[ -f "$LIB_DIR/lxc.sh" ] || LIB_DIR="$SCRIPT_DIR/../lib/mail"

# shellcheck source=/dev/null
source "$LIB_DIR/lxc.sh"
# shellcheck source=/dev/null
source "$LIB_DIR/migrate.sh"

log()  { echo "[mail-migrate] $*"; }
warn() { echo "[mail-migrate][WARN] $*" >&2; }

main() {
    [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

    : "${LXC_BASE:=/var/lib/lxc}"
    : "${DATA_PATH:=/data/volumes/mail}"

    log "Phase 1 scan starting (LXC_BASE=$LXC_BASE, DATA_PATH=$DATA_PATH)"

    # 1. Legacy LXCs (rev. 1 two-LXC layout). Not expected on this board.
    if legacy=$(detect_legacy_lxc 2>/dev/null); then
        warn "legacy LXC dirs present:"
        echo "$legacy" | sed 's/^/[mail-migrate][WARN]   - /' >&2
        warn "these are NOT removed automatically. To archive:"
        warn "  cd $LXC_BASE && tar -czf /tmp/legacy-mail-lxc-\$(date +%s).tar.gz mailserver roundcube"
    else
        log "no legacy mailserver/roundcube LXC dirs — clean"
    fi

    # 2. Data path — enforce invariant I13.
    if [ -d "$DATA_PATH/vmail" ]; then
        if guard_data_path 2>/dev/null; then
            log "data path $DATA_PATH/vmail is empty — fresh start ok"
        else
            log "data path $DATA_PATH/vmail has user data — preserving (per spec I13)"
        fi
    else
        log "data path $DATA_PATH/vmail does not exist yet"
    fi

    # 3. mail LXC presence.
    if lxc_exists "mail"; then
        log "mail LXC present at $LXC_BASE/mail"
    else
        warn "mail LXC not yet installed — run 'mailctl install' after this scanner"
    fi

    log "scan complete — no destructive actions taken"
}

main "$@"
