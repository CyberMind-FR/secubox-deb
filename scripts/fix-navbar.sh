#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SecuBox Navbar Integration Script
# Ensures all HTML pages have proper navbar/sidebar integration
# ═══════════════════════════════════════════════════════════════

set -e

WWW_DIR="${1:-/usr/share/secubox/www}"
FIXED=0
ERRORS=0

echo "🔧 SecuBox Navbar Integration Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Scanning: $WWW_DIR"
echo ""

for html in $(find "$WWW_DIR" -name "index.html" 2>/dev/null); do
    module=$(dirname "$html" | xargs basename)
    issues=""

    # Check for crt-light.css
    if ! grep -q 'crt-light.css' "$html" 2>/dev/null; then
        issues+="  ⚠ Missing crt-light.css\n"
        # Fix: Add before sidebar-light.css or at end of head
        if grep -q 'sidebar-light.css' "$html"; then
            sed -i 's|<link rel="stylesheet" href="/shared/sidebar-light.css">|<link rel="stylesheet" href="/shared/crt-light.css">\n    <link rel="stylesheet" href="/shared/sidebar-light.css">|' "$html"
        else
            sed -i 's|</head>|    <link rel="stylesheet" href="/shared/crt-light.css">\n</head>|' "$html"
        fi
    fi

    # Check for sidebar-light.css
    if ! grep -q 'sidebar-light.css' "$html" 2>/dev/null; then
        issues+="  ⚠ Missing sidebar-light.css\n"
        sed -i 's|</head>|    <link rel="stylesheet" href="/shared/sidebar-light.css">\n</head>|' "$html"
    fi

    # Check for sidebar.js
    if ! grep -q '/shared/sidebar.js' "$html" 2>/dev/null; then
        issues+="  ⚠ Missing /shared/sidebar.js\n"
        # Check if it uses wrong path
        if grep -q 'sidebar.js' "$html"; then
            sed -i 's|src="[^"]*sidebar.js"|src="/shared/sidebar.js"|g' "$html"
        else
            sed -i 's|</body>|    <script src="/shared/sidebar.js"></script>\n</body>|' "$html"
        fi
    fi

    # Check for body class
    if grep -q '<body>' "$html" 2>/dev/null; then
        issues+="  ⚠ Missing body class (should be crt-light)\n"
        sed -i 's/<body>/<body class="crt-light">/g' "$html"
    fi

    # Check for old dark theme class
    if grep -q 'crt-body crt-scanlines' "$html" 2>/dev/null; then
        issues+="  ⚠ Old dark theme body class\n"
        sed -i 's/class="crt-body crt-scanlines[^"]*"/class="crt-light"/g' "$html"
    fi

    # Check for sidebar nav element
    if ! grep -q '<nav class="sidebar" id="sidebar"' "$html" 2>/dev/null; then
        if ! grep -q 'id="sidebar"' "$html" 2>/dev/null; then
            issues+="  ⚠ Missing sidebar nav element\n"
        fi
    fi

    if [ -n "$issues" ]; then
        echo "📁 $module"
        echo -e "$issues"
        ((FIXED++))
    fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Fixed $FIXED modules"
echo ""
echo "Required elements for navbar integration:"
echo "  1. <link rel=\"stylesheet\" href=\"/shared/crt-light.css\">"
echo "  2. <link rel=\"stylesheet\" href=\"/shared/sidebar-light.css\">"
echo "  3. <body class=\"crt-light\">"
echo "  4. <nav class=\"sidebar\" id=\"sidebar\"></nav>"
echo "  5. <script src=\"/shared/sidebar.js\"></script>"
