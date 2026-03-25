#!/usr/bin/env python3
"""
Apply CRT Light Theme to all SecuBox UI modules
Updates CSS references and inline styles consistently
"""

import os
import re
import glob
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# CSS replacements
CSS_REPLACEMENTS = [
    # Replace dark theme CSS with light theme
    ('href="/shared/crt-system.css"', 'href="/shared/crt-light.css"'),
    ('href="/shared/sidebar.css"', 'href="/shared/sidebar-light.css"'),
    ("href='/shared/crt-system.css'", "href='/shared/crt-light.css'"),
    ("href='/shared/sidebar.css'", "href='/shared/sidebar-light.css'"),
]

# Color replacements for inline styles - dark to light
COLOR_REPLACEMENTS = [
    # Tube colors - dark to light
    ('--tube-black: #050803', '--tube-black: #e8f5e9'),
    ('--tube-deep: #080d05', '--tube-deep: #c8e6c9'),
    ('--tube-bezel: #0d1208', '--tube-bezel: #a5d6a7'),
    ('var(--tube-black)', 'var(--tube-light)'),
    ('var(--tube-deep)', 'var(--tube-pale)'),
    ('var(--tube-bezel)', 'var(--tube-soft)'),

    # Background colors
    ('background: #050803', 'background: #e8f5e9'),
    ('background: #080d05', 'background: #c8e6c9'),
    ('background:#050803', 'background:#e8f5e9'),
    ('background:#080d05', 'background:#c8e6c9'),

    # P31 colors - adjusted for lighter background
    ('--p31-peak: #33ff66', '--p31-peak: #00dd44'),
    ('--p31-hot: #66ffaa', '--p31-hot: #00ff55'),
    ('--p31-mid: #22cc44', '--p31-mid: #009933'),
    ('--p31-dim: #0f8822', '--p31-dim: #006622'),
    ('--p31-ghost: #052210', '--p31-ghost: #003311'),

    # Border and text colors
    ('border.*var\\(--p31-ghost\\)', 'border: 1px solid var(--tube-soft)'),
    ('color: var(--p31-mid)', 'color: var(--tube-dark)'),
]

# Light theme CSS variables to add
LIGHT_VARS = """
    --tube-light: #e8f5e9; --tube-pale: #c8e6c9; --tube-soft: #a5d6a7; --tube-mist: #81c784;
    --tube-dark: #1b3d1c;
    --p31-peak: #00dd44; --p31-hot: #00ff55; --p31-mid: #009933; --p31-dim: #006622; --p31-ghost: #003311;
    --p31-decay: #dd8800; --p31-decay-dim: #aa6600;
    --bg-dark: var(--tube-light); --bg-card: var(--tube-pale); --border: var(--tube-soft);
    --text: var(--tube-dark); --text-dim: var(--p31-dim);
"""

def update_html_file(filepath):
    """Update a single HTML file with light theme"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return False

    original = content
    changes = []

    # Apply CSS link replacements
    for old, new in CSS_REPLACEMENTS:
        if old in content:
            content = content.replace(old, new)
            changes.append(f"CSS: {old} -> {new}")

    # Update :root variables in inline styles
    if ':root' in content and ('--tube-black' in content or '--p31-peak: #33ff66' in content):
        # Find and update root variables
        root_pattern = r'(:root\s*\{[^}]*)'
        match = re.search(root_pattern, content, re.DOTALL)
        if match:
            root_content = match.group(1)

            # Update individual variables
            updates = [
                ('--tube-black: #050803', '--tube-light: #e8f5e9'),
                ('--tube-deep: #080d05', '--tube-pale: #c8e6c9'),
                ('--tube-bezel: #0d1208', '--tube-soft: #a5d6a7'),
                ('--p31-peak: #33ff66', '--p31-peak: #00dd44'),
                ('--p31-hot: #66ffaa', '--p31-hot: #00ff55'),
                ('--p31-mid: #22cc44', '--p31-mid: #009933'),
                ('--p31-dim: #0f8822', '--p31-dim: #006622'),
                ('--p31-ghost: #052210', '--p31-ghost: #003311'),
                ('--bg-dark: var(--tube-black)', '--bg-dark: var(--tube-light)'),
                ('--bg-card: var(--tube-deep)', '--bg-card: var(--tube-pale)'),
                ('--border: var(--p31-ghost)', '--border: var(--tube-soft)'),
                ('--text: var(--p31-mid)', '--text: var(--tube-dark)'),
            ]

            new_root = root_content
            for old_var, new_var in updates:
                if old_var in new_root:
                    new_root = new_root.replace(old_var, new_var)
                    changes.append(f"VAR: {old_var}")

            # Add missing light variables
            if '--tube-light' not in new_root and '--tube-black' not in new_root:
                # Add light variables after :root {
                new_root = new_root.replace(':root {', ':root {\n            --tube-light: #e8f5e9; --tube-pale: #c8e6c9; --tube-soft: #a5d6a7; --tube-mist: #81c784; --tube-dark: #1b3d1c;')
                changes.append("Added light tube variables")

            content = content.replace(root_content, new_root)

    # Update body background
    body_bg_patterns = [
        (r'body\s*\{([^}]*?)background:\s*var\(--tube-black\)', r'body {\1background: var(--tube-light)'),
        (r'body\s*\{([^}]*?)background:\s*#050803', r'body {\1background: #e8f5e9'),
        (r'body\s*\{([^}]*?)color:\s*var\(--p31-mid\)', r'body {\1color: var(--tube-dark)'),
    ]

    for pattern, replacement in body_bg_patterns:
        if re.search(pattern, content):
            content = re.sub(pattern, replacement, content)
            changes.append(f"Body style updated")

    # Update specific inline dark references
    inline_updates = [
        ('background: var(--tube-black)', 'background: var(--tube-light)'),
        ('background: var(--tube-deep)', 'background: var(--tube-pale)'),
        ('background:var(--tube-black)', 'background:var(--tube-light)'),
        ('background:var(--tube-deep)', 'background:var(--tube-pale)'),
        ('border-color: var(--p31-ghost)', 'border-color: var(--tube-soft)'),
        ('border: 1px solid var(--p31-ghost)', 'border: 1px solid var(--tube-soft)'),
    ]

    for old, new in inline_updates:
        if old in content:
            content = content.replace(old, new)
            changes.append(f"Inline: {old[:30]}...")

    # Write if changed
    if content != original:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return changes
        except Exception as e:
            print(f"  Error writing {filepath}: {e}")
            return False

    return []

def main():
    print("=" * 60)
    print("SecuBox Light Theme Applier")
    print("=" * 60)

    # Find all HTML files in packages/*/www/
    patterns = [
        str(BASE_DIR / "packages/*/www/**/*.html"),
        str(BASE_DIR / "packages/*/debian/*/usr/share/secubox/www/**/*.html"),
        str(BASE_DIR / "packages/*/debian/*/var/www/secubox/**/*.html"),
    ]

    html_files = []
    for pattern in patterns:
        html_files.extend(glob.glob(pattern, recursive=True))

    # Remove duplicates and sort
    html_files = sorted(set(html_files))

    print(f"\nFound {len(html_files)} HTML files")
    print("-" * 60)

    updated = 0
    skipped = 0
    errors = 0

    for filepath in html_files:
        rel_path = os.path.relpath(filepath, BASE_DIR)
        result = update_html_file(filepath)

        if result is False:
            errors += 1
            print(f"ERROR: {rel_path}")
        elif result:
            updated += 1
            print(f"UPDATED: {rel_path}")
            for change in result[:3]:  # Show first 3 changes
                print(f"  - {change}")
            if len(result) > 3:
                print(f"  ... and {len(result) - 3} more changes")
        else:
            skipped += 1

    print("-" * 60)
    print(f"Summary: {updated} updated, {skipped} unchanged, {errors} errors")
    print("=" * 60)

if __name__ == "__main__":
    main()
