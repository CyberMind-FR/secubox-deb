#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/apt-publish.sh
# Publish .deb packages to local APT repository with lintian validation
# SecuBox-DEB - CyberMind

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(dirname "$SCRIPT_DIR")"
readonly APT_LOCAL="/srv/apt"
readonly APT_CONF="$REPO_ROOT/apt/conf"
readonly HOOKS_DIR="$REPO_ROOT/apt/hooks"
readonly CODENAME="${CODENAME:-bookworm}"
readonly COMPONENT="${COMPONENT:-main}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <package.deb> [package2.deb ...]

Publish .deb packages to the SecuBox APT repository.

Options:
    -c, --codename NAME    Distribution codename (default: bookworm)
    -C, --component NAME   Component (default: main)
    -s, --skip-lintian     Skip lintian validation
    -n, --dry-run          Show what would be done
    -h, --help             Show this help message

Environment:
    CODENAME    Distribution codename (default: bookworm)
    COMPONENT   Component (default: main)

Examples:
    $(basename "$0") packages/secubox-core/*.deb
    $(basename "$0") -c bookworm-testing *.deb
    $(basename "$0") --skip-lintian packages/*/*.deb
EOF
}

init_repo() {
    if [ ! -d "$APT_LOCAL" ]; then
        echo -e "${YELLOW}Initializing APT repository at $APT_LOCAL...${NC}"
        sudo mkdir -p "$APT_LOCAL"/{conf,db,dists,pool,incoming,tmp}
        sudo cp "$APT_CONF"/* "$APT_LOCAL/conf/"
        sudo chown -R "$(whoami)" "$APT_LOCAL"

        # Initialize reprepro
        cd "$APT_LOCAL"
        reprepro export
        echo -e "${GREEN}Repository initialized.${NC}"
    fi
}

run_lintian() {
    local deb_file="$1"
    if [ -x "$HOOKS_DIR/lintian-check" ]; then
        "$HOOKS_DIR/lintian-check" "$deb_file"
    else
        echo -e "${YELLOW}Warning: lintian hook not found, skipping validation${NC}"
    fi
}

publish_package() {
    local deb_file="$1"
    local skip_lintian="$2"
    local dry_run="$3"
    local codename="$4"
    local component="$5"

    local pkg_name=$(dpkg-deb -f "$deb_file" Package 2>/dev/null || echo "unknown")
    local pkg_version=$(dpkg-deb -f "$deb_file" Version 2>/dev/null || echo "unknown")
    local pkg_arch=$(dpkg-deb -f "$deb_file" Architecture 2>/dev/null || echo "unknown")

    echo -e "Publishing: ${GREEN}${pkg_name}${NC} ${pkg_version} (${pkg_arch})"

    # Run lintian if not skipped
    if [ "$skip_lintian" != "true" ]; then
        if ! run_lintian "$deb_file"; then
            echo -e "${RED}Lintian validation failed for $deb_file${NC}"
            return 1
        fi
    fi

    if [ "$dry_run" = "true" ]; then
        echo -e "${YELLOW}DRY RUN: Would add to $codename/$component${NC}"
        return 0
    fi

    # Add to repository
    cd "$APT_LOCAL"
    reprepro -C "$component" includedeb "$codename" "$deb_file"

    echo -e "${GREEN}Added to repository: $codename/$component${NC}"
}

# Parse arguments
SKIP_LINTIAN=false
DRY_RUN=false
PACKAGES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--codename)
            CODENAME="$2"
            shift 2
            ;;
        -C|--component)
            COMPONENT="$2"
            shift 2
            ;;
        -s|--skip-lintian)
            SKIP_LINTIAN=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            PACKAGES+=("$1")
            shift
            ;;
    esac
done

if [ ${#PACKAGES[@]} -eq 0 ]; then
    echo "Error: No packages specified"
    usage
    exit 1
fi

# Initialize repository if needed
init_repo

# Publish packages
success=0
failed=0

for pkg in "${PACKAGES[@]}"; do
    if [ ! -f "$pkg" ]; then
        echo -e "${RED}File not found: $pkg${NC}"
        ((failed++))
        continue
    fi

    if [[ "$pkg" != *.deb ]]; then
        echo -e "${YELLOW}Skipping non-.deb file: $pkg${NC}"
        continue
    fi

    if publish_package "$pkg" "$SKIP_LINTIAN" "$DRY_RUN" "$CODENAME" "$COMPONENT"; then
        ((success++))
    else
        ((failed++))
    fi
done

echo ""
echo -e "Published: ${GREEN}$success${NC}  Failed: ${RED}$failed${NC}"

if [ $failed -gt 0 ]; then
    exit 1
fi
