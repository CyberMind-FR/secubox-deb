#!/usr/bin/env python3
"""
SecuBox-Deb :: CSS Design Token Updater
CyberMind — Gérald Kerma
Updates module CSS files to use the design-tokens.css system
"""

import os
import re
from pathlib import Path

# Map old colors to new design token variables
COLOR_MAP = {
    # P31 Phosphor legacy colors -> ROOT (green)
    '#00ff41': 'var(--root-light)',
    '#00ff00': 'var(--root-light)',
    '#33ff33': 'var(--root-light)',
    '#0a5840': 'var(--root-main)',
    '#148c66': 'var(--root-light)',
    '#10b981': 'var(--root-light)',
    '#22c55e': 'var(--root-light)',
    '#15803d': 'var(--root-main)',

    # Blue colors -> MESH
    '#3b82f6': 'var(--mesh-light)',
    '#06b6d4': 'var(--mesh-light)',
    '#104a88': 'var(--mesh-main)',
    '#0284c7': 'var(--mesh-light)',
    '#2563eb': 'var(--mesh-light)',

    # Orange colors -> AUTH
    '#c04e24': 'var(--auth-main)',
    '#e8845a': 'var(--auth-light)',
    '#f97316': 'var(--auth-light)',
    '#ea580c': 'var(--auth-main)',

    # Yellow/Amber colors -> WALL
    '#9a6010': 'var(--wall-main)',
    '#cc8820': 'var(--wall-light)',
    '#f59e0b': 'var(--wall-light)',
    '#d97706': 'var(--wall-main)',
    '#b45309': 'var(--wall-dark)',
    '#fbbf24': 'var(--wall-light)',

    # Red colors -> BOOT
    '#803018': 'var(--boot-main)',
    '#c06040': 'var(--boot-light)',
    '#ef4444': 'var(--boot-light)',
    '#dc2626': 'var(--boot-main)',
    '#b91c1c': 'var(--boot-dark)',
    '#f87171': 'var(--boot-light)',

    # Purple/Violet colors -> MIND
    '#3d35a0': 'var(--mind-main)',
    '#6366f1': 'var(--mind-light)',
    '#8b5cf6': 'var(--mind-light)',
    '#7c3aed': 'var(--mind-light)',
    '#764ba2': 'var(--mind-main)',
    '#a78bfa': 'var(--mind-light)',
    '#6e40c9': 'var(--mind-main)',
}

# Map --sh-* variables to design tokens
VAR_MAP = {
    '--sh-success': '--root-light',
    '--sh-danger': '--boot-light',
    '--sh-warning': '--wall-light',
    '--sh-info': '--mesh-light',
    '--sh-primary': '--mind-light',
    '--sh-primary-end': '--mind-main',
}

def get_import_path(css_path: Path) -> str:
    """Calculate relative path to shared/design-tokens.css"""
    parts = css_path.parts
    # Find www directory
    www_idx = -1
    for i, part in enumerate(parts):
        if part == 'www':
            www_idx = i
            break

    if www_idx == -1:
        return None

    # Count directories from css file to www
    depth = len(parts) - www_idx - 2  # -2 for www and filename
    rel_path = '../' * depth + 'shared/design-tokens.css'
    return rel_path

def update_css_file(filepath: Path) -> bool:
    """Update a CSS file with design token compliance"""
    try:
        content = filepath.read_text()
        original = content

        # Skip if already has design-tokens import
        if 'design-tokens.css' in content:
            print(f"  [SKIP] Already has design-tokens: {filepath.name}")
            return False

        # Skip design-tokens.css itself
        if filepath.name == 'design-tokens.css':
            return False

        # Get import path
        import_path = get_import_path(filepath)
        if not import_path:
            print(f"  [WARN] Could not determine import path for: {filepath}")
            return False

        # Add design-tokens import after existing imports or at top
        import_line = f"@import url('{import_path}');\n"

        # Find position for import (after any existing @import)
        lines = content.split('\n')
        insert_idx = 0
        in_comment = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('/*'):
                in_comment = True
            if '*/' in stripped:
                in_comment = False
                insert_idx = i + 1
                continue
            if not in_comment and stripped.startswith('@import'):
                insert_idx = i + 1

        # Insert design-tokens import
        if insert_idx == 0:
            # Add at very top
            lines.insert(0, import_line)
        else:
            lines.insert(insert_idx, import_line)

        content = '\n'.join(lines)

        # Replace hardcoded colors (case-insensitive)
        for old_color, new_var in COLOR_MAP.items():
            pattern = re.compile(re.escape(old_color), re.IGNORECASE)
            content = pattern.sub(new_var, content)

        # Update variable definitions to reference design tokens
        for old_var, new_var in VAR_MAP.items():
            # Replace in var() references
            content = re.sub(
                rf'var\({re.escape(old_var)}\)',
                f'var({new_var})',
                content
            )

        # Write updated content
        if content != original:
            filepath.write_text(content)
            print(f"  [OK] Updated: {filepath.name}")
            return True

        return False

    except Exception as e:
        print(f"  [ERR] {filepath}: {e}")
        return False

def main():
    base_path = Path('/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages')

    # Find all CSS files in www directories (excluding debian/)
    css_files = []
    for css_file in base_path.glob('**/www/**/*.css'):
        if '/debian/' not in str(css_file) and css_file.name != 'design-tokens.css':
            css_files.append(css_file)

    print(f"Found {len(css_files)} CSS files to update")
    print("=" * 60)

    updated = 0
    skipped = 0

    for css_file in sorted(css_files):
        rel_path = css_file.relative_to(base_path)
        print(f"\nProcessing: {rel_path}")

        if update_css_file(css_file):
            updated += 1
        else:
            skipped += 1

    print("\n" + "=" * 60)
    print(f"Summary: {updated} updated, {skipped} skipped")

if __name__ == '__main__':
    main()
