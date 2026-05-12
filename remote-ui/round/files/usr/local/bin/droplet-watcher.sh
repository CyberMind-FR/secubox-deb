#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Eye Remote — Droplet Watcher Service
# Monitors for new configuration patches and applies them automatically
#
# CyberMind — https://cybermind.fr

set -euo pipefail

PATCHES_DIR="/data/configs/shadow/patches"
LOCKFILE="/data/configs/lockfile"
LOG_TAG="droplet-watcher"

log() { logger -t "$LOG_TAG" "$*"; echo "[$(date '+%H:%M:%S')] $*"; }
err() { logger -t "$LOG_TAG" -p user.err "$*"; echo "[$(date '+%H:%M:%S')] ERROR: $*" >&2; }

# Ensure directories exist
mkdir -p "$PATCHES_DIR"

log "Droplet watcher started, monitoring: $PATCHES_DIR"

# Use inotifywait if available, otherwise poll
if command -v inotifywait &>/dev/null; then
    log "Using inotify for file watching"

    while true; do
        # Wait for new files
        inotifywait -q -e create -e moved_to "$PATCHES_DIR" || {
            log "inotifywait interrupted, restarting..."
            sleep 2
            continue
        }

        # Small delay to ensure file is fully written
        sleep 1

        # Check for pending patches
        patch_count=$(ls "$PATCHES_DIR"/*.patch "$PATCHES_DIR"/*.toml 2>/dev/null | wc -l || echo 0)

        if [ "$patch_count" -gt 0 ]; then
            log "Detected $patch_count new patch(es), applying..."

            # Try to acquire lock
            if ( set -o noclobber; echo "{\"owner\":\"watcher\",\"pid\":$$}" > "$LOCKFILE" ) 2>/dev/null; then
                trap 'rm -f "$LOCKFILE"' EXIT

                # Run droplet-config to apply patches
                if /usr/local/bin/droplet-config.sh apply && /usr/local/bin/droplet-config.sh swap; then
                    log "Patches applied successfully"

                    # Notify eye-agent to reload config
                    if command -v systemctl &>/dev/null; then
                        systemctl reload secubox-eye-agent 2>/dev/null || true
                    fi
                else
                    err "Failed to apply patches"
                fi

                rm -f "$LOCKFILE"
                trap - EXIT
            else
                log "Lock held by another process, will retry on next change"
            fi
        fi
    done
else
    log "inotify not available, using polling (5s interval)"

    while true; do
        patch_count=$(ls "$PATCHES_DIR"/*.patch "$PATCHES_DIR"/*.toml 2>/dev/null | wc -l || echo 0)

        if [ "$patch_count" -gt 0 ]; then
            log "Found $patch_count pending patch(es)"

            # Try to acquire lock
            if ( set -o noclobber; echo "{\"owner\":\"watcher\",\"pid\":$$}" > "$LOCKFILE" ) 2>/dev/null; then
                trap 'rm -f "$LOCKFILE"' EXIT

                if /usr/local/bin/droplet-config.sh apply && /usr/local/bin/droplet-config.sh swap; then
                    log "Patches applied successfully"

                    # Notify eye-agent
                    if command -v systemctl &>/dev/null; then
                        systemctl reload secubox-eye-agent 2>/dev/null || true
                    fi
                else
                    err "Failed to apply patches"
                fi

                rm -f "$LOCKFILE"
                trap - EXIT
            fi
        fi

        sleep 5
    done
fi
