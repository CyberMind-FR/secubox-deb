#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/apt-sync.sh
# Sync local APT repository to apt.secubox.in
# SecuBox-DEB - CyberMind

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(dirname "$SCRIPT_DIR")"
readonly APT_LOCAL="/srv/apt"
readonly APT_REMOTE="apt.secubox.in:/srv/apt"
readonly LOG_FILE="/var/log/secubox/apt-sync.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Sync local APT repository to apt.secubox.in

Options:
    -n, --dry-run     Show what would be synced without doing it
    -f, --force       Force sync even if no changes detected
    -v, --verbose     Verbose output
    -h, --help        Show this help message

Examples:
    $(basename "$0")              # Normal sync
    $(basename "$0") --dry-run    # Preview changes
    $(basename "$0") --force      # Force full sync
EOF
}

check_deps() {
    local missing=()
    for cmd in rsync reprepro ssh; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

check_repo() {
    if [ ! -d "$APT_LOCAL" ]; then
        log "ERROR" "Local repository not found: $APT_LOCAL"
        exit 1
    fi

    if [ ! -f "$APT_LOCAL/conf/distributions" ]; then
        log "ERROR" "Repository not initialized. Run 'reprepro export' first."
        exit 1
    fi
}

sync_repo() {
    local dry_run="${1:-false}"
    local verbose="${2:-false}"

    local rsync_opts="-avz --delete"
    if [ "$dry_run" = "true" ]; then
        rsync_opts="$rsync_opts --dry-run"
    fi
    if [ "$verbose" = "true" ]; then
        rsync_opts="$rsync_opts --progress"
    fi

    log "INFO" "Syncing $APT_LOCAL to $APT_REMOTE..."

    # Sync dists/ and pool/
    rsync $rsync_opts \
        --include='dists/***' \
        --include='pool/***' \
        --exclude='conf/' \
        --exclude='db/' \
        --exclude='incoming/' \
        --exclude='tmp/' \
        "$APT_LOCAL/" \
        "$APT_REMOTE/"

    local rc=$?
    if [ $rc -eq 0 ]; then
        log "INFO" "${GREEN}Sync completed successfully${NC}"
    else
        log "ERROR" "${RED}Sync failed with exit code $rc${NC}"
        exit $rc
    fi
}

# Parse arguments
DRY_RUN=false
FORCE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main
check_deps
check_repo

# Create log directory if needed
mkdir -p "$(dirname "$LOG_FILE")"

log "INFO" "Starting APT repository sync..."

if [ "$DRY_RUN" = "true" ]; then
    log "INFO" "${YELLOW}DRY RUN - no changes will be made${NC}"
fi

sync_repo "$DRY_RUN" "$VERBOSE"

log "INFO" "Done."
