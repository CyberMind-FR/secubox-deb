#!/usr/bin/env bash
# SecuBox-Deb :: sync-wiki.sh
# CyberMind — Gérald Kerma
# Sync wiki/ folder to GitHub wiki repository
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WIKI_SOURCE="${REPO_ROOT}/wiki"
WIKI_REPO_URL="git@github.com:CyberMind-FR/secubox-deb.wiki.git"
WIKI_CLONE_DIR="/tmp/secubox-wiki-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[WIKI]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Sync wiki/ folder to GitHub wiki repository.

Options:
    -m, --message MSG   Commit message (default: "Update wiki from main repo")
    -n, --dry-run       Show what would be done without making changes
    -p, --push          Push changes to GitHub wiki repo
    -h, --help          Show this help

Workflow:
    1. Clones the wiki repo to temp directory
    2. Copies all files from wiki/ to wiki repo
    3. Commits changes (with -p flag, pushes to GitHub)

Examples:
    $(basename "$0") -n              # Dry run - show changes
    $(basename "$0") -p              # Sync and push
    $(basename "$0") -p -m "Add Eye-Remote docs"

Note:
    GitHub wiki is a separate git repository from the main project.
    Files in wiki/ folder must be synced to the wiki repo separately.
EOF
    exit 0
}

COMMIT_MSG="Update wiki from main repo"
DRY_RUN=false
DO_PUSH=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--message) COMMIT_MSG="$2"; shift 2 ;;
            -n|--dry-run) DRY_RUN=true; shift ;;
            -p|--push) DO_PUSH=true; shift ;;
            -h|--help) usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done
}

check_source() {
    [[ -d "$WIKI_SOURCE" ]] || err "Wiki source not found: $WIKI_SOURCE"
    local count
    count=$(find "$WIKI_SOURCE" -name "*.md" | wc -l)
    log "Found $count markdown files in wiki/"
}

clone_wiki_repo() {
    log "Cloning wiki repository..."

    if $DRY_RUN; then
        log "[DRY RUN] Would clone: $WIKI_REPO_URL"
        return
    fi

    # Cleanup on exit
    trap "rm -rf '$WIKI_CLONE_DIR'" EXIT

    git clone --depth 1 "$WIKI_REPO_URL" "$WIKI_CLONE_DIR" 2>/dev/null || {
        warn "Wiki repo doesn't exist yet. Create it on GitHub first:"
        warn "  1. Go to https://github.com/CyberMind-FR/secubox-deb"
        warn "  2. Click Wiki tab"
        warn "  3. Create first page (Home)"
        err "Cannot clone wiki repository"
    }

    log "Wiki repo cloned to: $WIKI_CLONE_DIR"
}

sync_files() {
    log "Syncing wiki files..."

    if $DRY_RUN; then
        log "[DRY RUN] Would copy files:"
        find "$WIKI_SOURCE" -name "*.md" -exec basename {} \;
        return
    fi

    # Remove old files (except .git)
    find "$WIKI_CLONE_DIR" -maxdepth 1 -name "*.md" -delete

    # Copy new files
    cp "$WIKI_SOURCE"/*.md "$WIKI_CLONE_DIR/"

    # Show diff
    cd "$WIKI_CLONE_DIR"
    if git diff --stat HEAD; then
        log "Files synced successfully"
    fi
}

commit_and_push() {
    if $DRY_RUN; then
        log "[DRY RUN] Would commit with message: $COMMIT_MSG"
        $DO_PUSH && log "[DRY RUN] Would push to origin"
        return
    fi

    cd "$WIKI_CLONE_DIR"

    # Check for changes
    if git diff --quiet HEAD; then
        log "No changes to commit"
        return
    fi

    # Stage and commit
    git add -A
    git commit -m "$COMMIT_MSG"
    log "Changes committed: $COMMIT_MSG"

    # Push if requested
    if $DO_PUSH; then
        log "Pushing to GitHub wiki..."
        git push origin master
        log "Wiki updated successfully!"
        log "View at: https://github.com/CyberMind-FR/secubox-deb/wiki"
    else
        warn "Changes committed locally. Use -p to push."
    fi
}

main() {
    parse_args "$@"

    log "SecuBox Wiki Sync"
    log "================="

    check_source
    clone_wiki_repo
    sync_files
    commit_and_push

    log "Done!"
}

main "$@"
