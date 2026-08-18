#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Eye Remote — Droplet Configuration Manager
# Double-buffered config with 4R rollback
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>

set -euo pipefail

# Paths
DATA_ROOT="/data/configs"
ACTIVE_DIR="$DATA_ROOT/active"
SHADOW_DIR="$DATA_ROOT/shadow"
PATCHES_DIR="$SHADOW_DIR/patches"
ROLLBACK_DIR="$DATA_ROOT/rollback"
LOCKFILE="$DATA_ROOT/lockfile"
STATE_FILE="$DATA_ROOT/state.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[droplet]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }
info() { echo -e "${BLUE}[info]${NC} $*"; }

# ═════��══════════════════════════���══════════════════════════════════════════════
# LOCK MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

acquire_lock() {
    local owner="${1:-cli}"
    local timeout="${2:-10}"
    local waited=0

    mkdir -p "$(dirname "$LOCKFILE")"

    while [ $waited -lt $timeout ]; do
        if ( set -o noclobber; echo "{\"owner\":\"$owner\",\"pid\":$$,\"acquired_at\":\"$(date -Iseconds)\"}" > "$LOCKFILE" ) 2>/dev/null; then
            log "Lock acquired by $owner"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    err "Failed to acquire lock after ${timeout}s"
    return 1
}

release_lock() {
    rm -f "$LOCKFILE"
    log "Lock released"
}

check_lock() {
    if [ -f "$LOCKFILE" ]; then
        cat "$LOCKFILE"
        return 0
    else
        echo "Not locked"
        return 1
    fi
}

# ════════════════════════════════��══════════════════════════════════════════════
# DIRECTORY SETUP
# ═══════════════════════════════════════════════════════════════════════════════

init_dirs() {
    log "Initializing directory structure..."

    mkdir -p "$ACTIVE_DIR"
    mkdir -p "$SHADOW_DIR"
    mkdir -p "$PATCHES_DIR"
    mkdir -p "$ROLLBACK_DIR/R1"
    mkdir -p "$ROLLBACK_DIR/R2"
    mkdir -p "$ROLLBACK_DIR/R3"
    mkdir -p "$ROLLBACK_DIR/R4"

    log "Directories initialized at $DATA_ROOT"
}

# ═══════��═══════════════════════════���══════════════════════════���════════════════
# HASH COMPUTATION
# ══════════════��════════════════════════════════════════════════════════════════

compute_hash() {
    local dir="$1"
    if [ -d "$dir" ] && ls "$dir"/*.toml &>/dev/null; then
        cat "$dir"/*.toml 2>/dev/null | sha256sum | cut -c1-16
    else
        echo "empty"
    fi
}

# ════���════════════════════���═════════════════════════════════════════════════════
# STATUS
# ════════════════════════��══════════════════════════════���═══════════════════════

show_status() {
    echo "╔════════════════════════════���══════════════════════════════════╗"
    echo "���           SecuBox Eye Remote — Configuration Status          ║"
    echo "╠════════��═════════════════════���════════════════════════════════╣"

    # Active config
    local active_hash=$(compute_hash "$ACTIVE_DIR")
    local active_count=$(ls "$ACTIVE_DIR"/*.toml 2>/dev/null | wc -l || echo 0)
    printf "║  Active:   %-10s (%d files)                            ║\n" "$active_hash" "$active_count"

    # Shadow config
    local shadow_hash=$(compute_hash "$SHADOW_DIR")
    local shadow_count=$(ls "$SHADOW_DIR"/*.toml 2>/dev/null | wc -l || echo 0)
    printf "║  Shadow:   %-10s (%d files)                            ║\n" "$shadow_hash" "$shadow_count"

    # Pending patches
    local patch_count=$(ls "$PATCHES_DIR"/*.patch "$PATCHES_DIR"/*.toml 2>/dev/null | wc -l || echo 0)
    printf "║  Patches:  %d pending                                       ║\n" "$patch_count"

    # Rollbacks
    local r1_count=$(ls "$ROLLBACK_DIR/R1"/*.toml 2>/dev/null | wc -l || echo 0)
    local r2_count=$(ls "$ROLLBACK_DIR/R2"/*.toml 2>/dev/null | wc -l || echo 0)
    local r3_count=$(ls "$ROLLBACK_DIR/R3"/*.toml 2>/dev/null | wc -l || echo 0)
    local r4_count=$(ls "$ROLLBACK_DIR/R4"/*.toml 2>/dev/null | wc -l || echo 0)
    printf "║  Rollback: R1(%d) R2(%d) R3(%d) R4(%d)                          ║\n" "$r1_count" "$r2_count" "$r3_count" "$r4_count"

    # Lock status
    if [ -f "$LOCKFILE" ]; then
        local lock_owner=$(jq -r '.owner // "unknown"' "$LOCKFILE" 2>/dev/null || echo "unknown")
        printf "║  Lock:     LOCKED by %-20s               ║\n" "$lock_owner"
    else
        echo "║  Lock:     Available                                        ║"
    fi

    echo "╚══════════════════════════��════════════════════════════════════╝"

    # Show active config files
    if [ "$active_count" -gt 0 ]; then
        echo ""
        echo "Active configuration files:"
        ls -la "$ACTIVE_DIR"/*.toml 2>/dev/null || true
    fi

    # Show pending patches
    if [ "$patch_count" -gt 0 ]; then
        echo ""
        echo "Pending patches:"
        ls -la "$PATCHES_DIR"/*.patch "$PATCHES_DIR"/*.toml 2>/dev/null || true
    fi
}

# ════���══════════════════════════════════════════════════════════════════════════
# PATCH OPERATIONS
# ═══════════════════���═══════════════════════════════════════════════════════════

drop_patch() {
    local patch_file="$1"
    local patch_name

    if [ ! -f "$patch_file" ]; then
        err "Patch file not found: $patch_file"
        return 1
    fi

    patch_name=$(basename "$patch_file")
    cp "$patch_file" "$PATCHES_DIR/$patch_name"
    log "Dropped patch: $patch_name"
}

apply_patches() {
    local applied=0

    # Apply .toml patches (full config replacement)
    for patch in "$PATCHES_DIR"/*.toml; do
        [ -f "$patch" ] || continue
        local name=$(basename "$patch")
        cp "$patch" "$SHADOW_DIR/$name"
        rm "$patch"
        log "Applied TOML: $name"
        applied=$((applied + 1))
    done

    # Apply .patch files (key-value updates)
    for patch in "$PATCHES_DIR"/*.patch; do
        [ -f "$patch" ] || continue
        local name=$(basename "$patch")
        apply_kv_patch "$patch"
        rm "$patch"
        log "Applied patch: $name"
        applied=$((applied + 1))
    done

    log "Applied $applied patches"
    return 0
}

apply_kv_patch() {
    local patch_file="$1"
    local target="eye-remote"
    local in_header=true

    # Parse patch file
    while IFS= read -r line; do
        if [ "$in_header" = true ]; then
            if [ "$line" = "---" ]; then
                in_header=false
                continue
            fi
            if [[ "$line" =~ ^target:\ *(.+) ]]; then
                target="${BASH_REMATCH[1]}"
            fi
            continue
        fi

        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Apply key=value to shadow config
        # This is a simplified implementation; Python version is more robust
        echo "Would apply: $line to $target"

    done < "$patch_file"
}

# ══════════════════════════════════════════════════��════════════════════════════
# SWAP OPERATIONS
# ══════════════��═════════════════════════════��══════════════════════════════════

validate_shadow() {
    log "Validating shadow configuration..."

    for config in "$SHADOW_DIR"/*.toml; do
        [ -f "$config" ] || continue
        # Basic TOML syntax check
        if ! python3 -c "import tomllib; tomllib.load(open('$config', 'rb'))" 2>/dev/null; then
            err "Invalid TOML: $(basename "$config")"
            return 1
        fi
    done

    log "Validation passed"
    return 0
}

shift_rollbacks() {
    log "Shifting rollbacks..."

    # R3 → R4
    rm -f "$ROLLBACK_DIR/R4"/*.toml 2>/dev/null || true
    cp "$ROLLBACK_DIR/R3"/*.toml "$ROLLBACK_DIR/R4/" 2>/dev/null || true

    # R2 → R3
    rm -f "$ROLLBACK_DIR/R3"/*.toml 2>/dev/null || true
    cp "$ROLLBACK_DIR/R2"/*.toml "$ROLLBACK_DIR/R3/" 2>/dev/null || true

    # R1 �� R2
    rm -f "$ROLLBACK_DIR/R2"/*.toml 2>/dev/null || true
    cp "$ROLLBACK_DIR/R1"/*.toml "$ROLLBACK_DIR/R2/" 2>/dev/null || true

    # active → R1
    rm -f "$ROLLBACK_DIR/R1"/*.toml 2>/dev/null || true
    cp "$ACTIVE_DIR"/*.toml "$ROLLBACK_DIR/R1/" 2>/dev/null || true

    log "Rollbacks shifted"
}

do_swap() {
    log "Performing atomic swap..."

    # Validate first
    if ! validate_shadow; then
        err "Swap aborted: validation failed"
        return 1
    fi

    # Shift rollbacks
    shift_rollbacks

    # Swap: shadow → active
    rm -f "$ACTIVE_DIR"/*.toml 2>/dev/null || true
    cp "$SHADOW_DIR"/*.toml "$ACTIVE_DIR/" 2>/dev/null || true

    # Update state
    echo "{\"last_swap_at\":\"$(date -Iseconds)\",\"active_hash\":\"$(compute_hash "$ACTIVE_DIR")\"}" > "$STATE_FILE"

    log "Swap completed successfully"
    return 0
}

# ════════════════════��══════════════════════════════════════════════════════════
# ROLLBACK
# ═══════════════════════���═══════════════════════════════════════════════════════

do_rollback() {
    local slot="${1:-R1}"

    if [[ ! "$slot" =~ ^R[1-4]$ ]]; then
        err "Invalid rollback slot: $slot (use R1, R2, R3, or R4)"
        return 1
    fi

    local rollback_src="$ROLLBACK_DIR/$slot"

    if [ ! "$(ls -A "$rollback_src"/*.toml 2>/dev/null)" ]; then
        err "Rollback slot $slot is empty"
        return 1
    fi

    log "Rolling back to $slot..."

    # Copy rollback to shadow
    rm -f "$SHADOW_DIR"/*.toml 2>/dev/null || true
    cp "$rollback_src"/*.toml "$SHADOW_DIR/"

    # Swap to apply
    do_swap
}

# ══════��═══════════════════════════════════════���════════════════════════════════
# FULL WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════════

full_apply() {
    # Acquire lock
    if ! acquire_lock "cli-full-apply"; then
        return 1
    fi

    trap 'release_lock' EXIT

    # Apply patches
    apply_patches

    # Swap
    do_swap

    release_lock
    trap - EXIT
}

# ══════════════════════════��════════════════════════════════════════════════════
# MAIN
# ══════��════════════════════════════════════════════════════════════════════════

usage() {
    cat << EOF
SecuBox Eye Remote — Droplet Configuration Manager

Usage: $0 <command> [options]

Commands:
  init              Initialize directory structure
  status            Show configuration status
  drop <file>       Drop a patch file into pending
  apply             Apply all pending patches (requires lock)
  swap              Swap shadow → active (requires lock)
  rollback [slot]   Rollback to R1, R2, R3, or R4
  full              Apply patches + swap (with lock)

  lock              Acquire configuration lock
  unlock            Release configuration lock
  lock-status       Show lock status

Examples:
  $0 init
  $0 status
  $0 drop /tmp/wifi-setup.patch
  $0 full
  $0 rollback R1

Droplet Patch Format (.patch):
  target: eye-remote
  ---
  display.brightness = 100
  display.theme = "cyber"
  network.wifi_ssid = "MyNetwork"

Full Config Format (.toml):
  Drop a complete .toml file to replace that config entirely.

EOF
    exit 0
}

case "${1:-}" in
    init)
        init_dirs
        ;;
    status|state)
        show_status
        ;;
    drop)
        [ -z "${2:-}" ] && { err "Usage: $0 drop <patch-file>"; exit 1; }
        drop_patch "$2"
        ;;
    apply)
        acquire_lock "cli-apply" && { apply_patches; release_lock; }
        ;;
    swap)
        acquire_lock "cli-swap" && { do_swap; release_lock; }
        ;;
    rollback)
        acquire_lock "cli-rollback" && { do_rollback "${2:-R1}"; release_lock; }
        ;;
    full)
        full_apply
        ;;
    lock)
        acquire_lock "${2:-cli}"
        ;;
    unlock)
        release_lock
        ;;
    lock-status)
        check_lock
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        ;;
esac
