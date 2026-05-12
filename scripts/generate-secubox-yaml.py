#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: generate-secubox-yaml.py
Generate debian/secubox.yaml files from existing debian/control files.

Usage:
    python3 scripts/generate-secubox-yaml.py
    python3 scripts/generate-secubox-yaml.py packages/secubox-crowdsec

CyberMind - Gerald Kerma
"""

import sys
from typing import Optional
import re
from pathlib import Path

# Category mapping based on package name patterns
CATEGORY_MAP = {
    # Security
    r'crowdsec|waf|auth|firewall|nac|hardening|cve|guardian': 'security',
    # Network
    r'wireguard|vpn|netmodes|network|dns|vortex|ddns|haproxy': 'network',
    # Monitoring
    r'netdata|metrics|grafana|prometheus|health|doctor': 'monitoring',
    # System
    r'core|system|hub|portal|admin|backup|config|daemon': 'system',
    # Media
    r'jellyfin|media|stream|plex|dlna': 'media',
    # AI
    r'ollama|ai-|llm|copilot|insights': 'ai',
    # Publishing
    r'metablog|publish|blog|cms|gitea|wiki': 'publishing',
    # Dashboard
    r'dashboard|c3box|soc|eye-remote': 'dashboard',
    # VPN
    r'tailscale|zerotier|nebula|mesh': 'vpn',
    # Email
    r'email|mail|smtp|imap': 'email',
    # IoT
    r'iot|mqtt|zigbee|zwave|home': 'iot',
    # Communication
    r'matrix|signal|chat|voice': 'communication',
}

# Tier mapping: packages exclusive to certain tiers
TIER_EXCLUSIVE = {
    'pro': [
        'secubox-dpi',
        'secubox-ollama',
        'secubox-jellyfin',
        'secubox-matrix',
        'secubox-nextcloud',
        'secubox-gitea',
        'secubox-ai-gateway',
        'secubox-ai-insights',
    ],
    'standard': [
        'secubox-qos',
        'secubox-cdn',
        'secubox-waf',
        'secubox-haproxy',
    ],
}

# Packages required for all tiers
REQUIRED_ALL = [
    'secubox-core',
    'secubox-hub',
    'secubox-portal',
    'secubox-system',
]


def detect_category(pkg_name: str) -> str:
    """Detect category from package name."""
    name_lower = pkg_name.lower().replace('secubox-', '')
    for pattern, category in CATEGORY_MAP.items():
        if re.search(pattern, name_lower):
            return category
    return 'misc'


def detect_tier(pkg_name: str) -> str:
    """Detect minimum tier for package."""
    if pkg_name in REQUIRED_ALL:
        return 'all'
    for tier, packages in TIER_EXCLUSIVE.items():
        if pkg_name in packages:
            return tier
    return 'lite'  # Available on all tiers by default


def parse_control(control_path: Path) -> dict:
    """Parse debian/control file and extract metadata."""
    content = control_path.read_text()

    result = {
        'source': '',
        'package': '',
        'section': 'misc',
        'architecture': 'all',
        'depends': [],
        'recommends': [],
        'description': '',
        'description_long': '',
    }

    # Parse Source stanza
    source_match = re.search(r'^Source:\s*(.+)$', content, re.MULTILINE)
    if source_match:
        result['source'] = source_match.group(1).strip()

    # Parse Package stanza
    pkg_match = re.search(r'^Package:\s*(.+)$', content, re.MULTILINE)
    if pkg_match:
        result['package'] = pkg_match.group(1).strip()

    # Parse Section
    section_match = re.search(r'^Section:\s*(.+)$', content, re.MULTILINE)
    if section_match:
        result['section'] = section_match.group(1).strip()

    # Parse Architecture
    arch_match = re.search(r'^Architecture:\s*(.+)$', content, re.MULTILINE)
    if arch_match:
        result['architecture'] = arch_match.group(1).strip()

    # Parse Depends (multi-line capable)
    depends_match = re.search(r'^Depends:\s*(.+?)(?=^[A-Z]|\Z)', content, re.MULTILINE | re.DOTALL)
    if depends_match:
        deps_raw = depends_match.group(1)
        # Clean up and split
        deps_clean = re.sub(r'\s+', ' ', deps_raw).strip()
        deps_list = [d.strip() for d in deps_clean.split(',') if d.strip()]
        # Extract just package names (remove version constraints, alternatives)
        deps_names = []
        for dep in deps_list:
            # Skip ${misc:Depends} etc
            if dep.startswith('$'):
                continue
            # Handle alternatives (a | b)
            if '|' in dep:
                parts = dep.split('|')
                dep = parts[0].strip()
            # Remove version constraints
            dep = re.sub(r'\s*\([^)]+\)', '', dep).strip()
            if dep and not dep.startswith('$'):
                deps_names.append(dep)
        result['depends'] = deps_names

    # Parse Recommends
    recommends_match = re.search(r'^Recommends:\s*(.+)$', content, re.MULTILINE)
    if recommends_match:
        recs_raw = recommends_match.group(1)
        recs_clean = re.sub(r'\s+', ' ', recs_raw).strip()
        recs_list = [r.strip() for r in recs_clean.split(',') if r.strip()]
        result['recommends'] = recs_list

    # Parse Description
    desc_match = re.search(r'^Description:\s*(.+?)(?=^[A-Z]|\Z)', content, re.MULTILINE | re.DOTALL)
    if desc_match:
        desc_lines = desc_match.group(1).strip().split('\n')
        result['description'] = desc_lines[0].strip()
        if len(desc_lines) > 1:
            # Long description is indented with space or dot
            long_desc = []
            for line in desc_lines[1:]:
                line = line.strip()
                if line.startswith('.'):
                    long_desc.append('')
                elif line:
                    long_desc.append(line)
            result['description_long'] = '\n'.join(long_desc)

    return result


def generate_secubox_yaml(pkg_dir: Path) -> Optional[str]:
    """Generate secubox.yaml content for a package."""
    control_path = pkg_dir / 'debian' / 'control'
    if not control_path.exists():
        return None

    meta = parse_control(control_path)
    pkg_name = meta['package'] or pkg_dir.name

    category = detect_category(pkg_name)
    tier = detect_tier(pkg_name)

    # Filter secubox-* dependencies
    secubox_deps = [d for d in meta['depends'] if d.startswith('secubox-')]

    lines = [
        f"# debian/secubox.yaml",
        f"# Auto-generated from debian/control",
        f"",
        f"name: {pkg_name}",
        f"category: {category}",
        f"tier: {tier}",
    ]

    if meta['description']:
        lines.append(f"description: \"{meta['description']}\"")

    if secubox_deps:
        lines.append(f"")
        lines.append(f"depends:")
        for dep in secubox_deps:
            lines.append(f"  - {dep}")

    # Check for API socket
    api_path = pkg_dir / 'api' / 'main.py'
    if api_path.exists():
        lines.append(f"")
        lines.append(f"api:")
        lines.append(f"  socket: /run/secubox/{pkg_name.replace('secubox-', '')}.sock")
        lines.append(f"  health: /api/v1/{pkg_name.replace('secubox-', '')}/health")

    # Check for www/ directory
    www_path = pkg_dir / 'www'
    if www_path.exists():
        lines.append(f"")
        lines.append(f"ui:")
        lines.append(f"  path: /srv/secubox/www/{pkg_name.replace('secubox-', '')}")

    lines.append("")
    return '\n'.join(lines)


def process_package(pkg_dir: Path) -> bool:
    """Process a single package directory."""
    yaml_content = generate_secubox_yaml(pkg_dir)
    if yaml_content is None:
        print(f"  SKIP: {pkg_dir.name} (no debian/control)")
        return False

    yaml_path = pkg_dir / 'debian' / 'secubox.yaml'

    # Don't overwrite if exists with custom content
    if yaml_path.exists():
        existing = yaml_path.read_text()
        if '# Custom' in existing or '# Manual' in existing:
            print(f"  SKIP: {pkg_dir.name} (custom secubox.yaml)")
            return False

    yaml_path.write_text(yaml_content)
    print(f"  OK: {pkg_dir.name}")
    return True


def main():
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    packages_dir = repo_root / 'packages'

    if len(sys.argv) > 1:
        # Process specific package(s)
        for pkg_path in sys.argv[1:]:
            pkg_dir = Path(pkg_path)
            if not pkg_dir.is_absolute():
                pkg_dir = repo_root / pkg_path
            if pkg_dir.exists():
                process_package(pkg_dir)
            else:
                print(f"  ERROR: {pkg_path} not found")
    else:
        # Process all packages
        print(f"Generating secubox.yaml for packages in {packages_dir}...")
        count = 0
        for pkg_dir in sorted(packages_dir.iterdir()):
            if pkg_dir.is_dir() and (pkg_dir / 'debian').exists():
                if process_package(pkg_dir):
                    count += 1
        print(f"\nGenerated {count} secubox.yaml files")


if __name__ == '__main__':
    main()
