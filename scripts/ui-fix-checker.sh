#!/bin/bash
# SecuBox UI Fix Checker
# Scans all modules for UI guideline compliance and reports issues
#
# Usage: ./scripts/ui-fix-checker.sh [--fix]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGES_DIR="$BASE_DIR/packages"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FIX_MODE=false
[[ "${1:-}" == "--fix" ]] && FIX_MODE=true

TOTAL_CHECKED=0
TOTAL_ISSUES=0
TOTAL_FIXED=0

log() { echo -e "${CYAN}[CHECK]${NC} $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err() { echo -e "${RED}[ERR]${NC} $1"; }

# Required elements from UI-GUIDE.md
check_html_file() {
    local file="$1"
    local module="$2"
    local issues=()
    local basename=$(basename "$file")

    # Skip special pages that intentionally don't have sidebars
    if [[ "$basename" == "login.html" ]] || \
       [[ "$basename" == *"-standalone.html" ]] || \
       [[ "$file" == *"/master-link/"* ]]; then
        ok "$module: $basename (skipped - special page)"
        return
    fi

    # Check for sidebar inclusion
    if ! grep -q 'id="sidebar"\|class="sidebar"' "$file" 2>/dev/null; then
        issues+=("Missing sidebar container")
    fi

    # Check for main-content class (or class containing "main")
    if ! grep -qE 'class="[^"]*main[^"]*"' "$file" 2>/dev/null; then
        issues+=("Missing main/main-content class")
    fi

    # Check for CRT theme CSS
    if ! grep -q 'crt-light.css\|crt-system.css' "$file" 2>/dev/null; then
        issues+=("Missing CRT theme CSS link")
    fi

    # Check for sidebar.js inclusion
    if ! grep -q 'sidebar.js' "$file" 2>/dev/null; then
        issues+=("Missing sidebar.js script")
    fi

    # Check for proper DOCTYPE
    if ! grep -q '<!DOCTYPE html>' "$file" 2>/dev/null; then
        issues+=("Missing DOCTYPE declaration")
    fi

    # Check for lang attribute
    if ! grep -q '<html lang=' "$file" 2>/dev/null; then
        issues+=("Missing lang attribute on html tag")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        err "$module: $(basename "$file")"
        for issue in "${issues[@]}"; do
            echo "       - $issue"
        done
        TOTAL_ISSUES=$((TOTAL_ISSUES + ${#issues[@]}))

        if $FIX_MODE; then
            fix_html_file "$file" "${issues[@]}"
        fi
    else
        ok "$module: $(basename "$file")"
    fi

    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
}

fix_html_file() {
    local file="$1"
    shift
    local issues=("$@")

    for issue in "${issues[@]}"; do
        case "$issue" in
            "Missing sidebar container")
                # Add sidebar container after <body>
                if grep -q '<body' "$file"; then
                    sed -i 's/<body[^>]*>/<body class="crt-light">\n    <nav class="sidebar" id="sidebar"><\/nav>/' "$file"
                    warn "Fixed: Added sidebar container to $file"
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                fi
                ;;
            "Missing main-content class")
                # This requires more context-aware fixing
                warn "Manual fix needed: Add class=\"main-content\" to main container in $file"
                ;;
            "Missing CRT theme CSS link")
                # Add CSS link in head
                if grep -q '</head>' "$file"; then
                    sed -i 's|</head>|    <link rel="stylesheet" href="/shared/crt-light.css">\n    <link rel="stylesheet" href="/shared/sidebar-light.css">\n</head>|' "$file"
                    warn "Fixed: Added CRT theme CSS to $file"
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                fi
                ;;
            "Missing sidebar.js script")
                # Add script before </body>
                if grep -q '</body>' "$file"; then
                    sed -i 's|</body>|    <script src="/shared/sidebar.js"></script>\n</body>|' "$file"
                    warn "Fixed: Added sidebar.js to $file"
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                fi
                ;;
            "Missing DOCTYPE declaration")
                # Add DOCTYPE at start
                if ! grep -q '<!DOCTYPE' "$file"; then
                    sed -i '1s/^/<!DOCTYPE html>\n/' "$file"
                    warn "Fixed: Added DOCTYPE to $file"
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                fi
                ;;
        esac
    done
}

# Check CSS files for proper variables
check_css_file() {
    local file="$1"
    local module="$2"
    local issues=()

    # Check for CRT color variables
    if grep -q 'background\|color' "$file" 2>/dev/null; then
        if ! grep -q 'var(--\|#e8f5e9\|#0a0e14' "$file" 2>/dev/null; then
            issues+=("Uses hardcoded colors instead of CSS variables")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        warn "$module: $(basename "$file")"
        for issue in "${issues[@]}"; do
            echo "       - $issue"
        done
    fi
}

# Check menu.json files
check_menu_json() {
    local file="$1"
    local module="$2"
    local issues=()

    # Validate JSON
    if ! python3 -m json.tool "$file" > /dev/null 2>&1; then
        issues+=("Invalid JSON syntax")
    else
        # Check required fields
        if ! grep -q '"id"' "$file"; then
            issues+=("Missing 'id' field")
        fi
        if ! grep -q '"name"' "$file"; then
            issues+=("Missing 'name' field")
        fi
        if ! grep -q '"path"' "$file"; then
            issues+=("Missing 'path' field")
        fi
        if ! grep -q '"category"' "$file"; then
            issues+=("Missing 'category' field")
        fi
        if ! grep -q '"icon"' "$file"; then
            issues+=("Missing 'icon' field")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        err "$module: $(basename "$file")"
        for issue in "${issues[@]}"; do
            echo "       - $issue"
        done
        TOTAL_ISSUES=$((TOTAL_ISSUES + ${#issues[@]}))
    fi
}

echo "SecuBox UI Guideline Checker"
echo "============================"
echo "Mode: $(if $FIX_MODE; then echo "FIX"; else echo "CHECK ONLY (use --fix to auto-fix)"; fi)"
echo ""

# Find all packages with www/ directory
for pkg_dir in "$PACKAGES_DIR"/secubox-*/; do
    pkg=$(basename "$pkg_dir")
    www_dir="$pkg_dir/www"

    if [[ -d "$www_dir" ]]; then
        log "Checking $pkg..."

        # Check HTML files
        find "$www_dir" -name "*.html" -type f 2>/dev/null | while read -r html_file; do
            check_html_file "$html_file" "$pkg"
        done

        # Check menu.json
        menu_file="$pkg_dir/etc/secubox/menu.d/${pkg#secubox-}.json"
        [[ -f "$menu_file" ]] && check_menu_json "$menu_file" "$pkg"

        # Check for custom CSS
        find "$www_dir" -name "*.css" -type f 2>/dev/null | while read -r css_file; do
            check_css_file "$css_file" "$pkg"
        done
    fi
done

echo ""
echo "Summary"
echo "-------"
echo "Files checked: $TOTAL_CHECKED"
echo "Issues found: $TOTAL_ISSUES"
if $FIX_MODE; then
    echo "Issues fixed: $TOTAL_FIXED"
fi

if [[ $TOTAL_ISSUES -gt 0 ]] && ! $FIX_MODE; then
    echo ""
    echo "Run with --fix to auto-fix some issues:"
    echo "  ./scripts/ui-fix-checker.sh --fix"
fi

exit $([[ $TOTAL_ISSUES -eq 0 ]] && echo 0 || echo 1)
