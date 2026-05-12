#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add /health endpoint to all SecuBox module APIs.

Adds a simple health check endpoint that returns:
- status: "ok" | "degraded" | "error"
- module: module name
- uptime: service uptime if available

Usage:
    python scripts/add-health-endpoints.py [--dry-run]
"""
import re
import sys
from pathlib import Path

PACKAGES_DIR = Path(__file__).parent.parent / "packages"

# Health endpoint code to inject
HEALTH_ENDPOINT = '''
# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": MODULE_NAME}
'''

# Alternative for modules without MODULE_NAME
HEALTH_ENDPOINT_INLINE = '''
# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {{"status": "ok", "module": "{module}"}}
'''


def get_module_name(path: Path) -> str:
    """Extract module name from path."""
    # packages/secubox-ai-gateway/api/main.py -> ai-gateway
    parts = path.parts
    for i, p in enumerate(parts):
        if p.startswith("secubox-"):
            return p[8:]  # Remove 'secubox-' prefix
    return "unknown"


def has_health_endpoint(content: str) -> bool:
    """Check if file already has a /health endpoint."""
    return bool(re.search(r'@app\.(get|post)\s*\(\s*["\']/?health["\']', content, re.IGNORECASE))


def find_injection_point(content: str) -> int:
    """Find best place to inject health endpoint (after imports, before routes)."""
    # Try to find the first @app.get or @app.post
    match = re.search(r'^@app\.(get|post)', content, re.MULTILINE)
    if match:
        return match.start()

    # Fallback: find 'app = FastAPI' and inject after
    match = re.search(r'app\s*=\s*FastAPI\([^)]*\)\s*\n', content)
    if match:
        return match.end()

    return -1


def add_health_endpoint(filepath: Path, dry_run: bool = False) -> bool:
    """Add health endpoint to a module's main.py."""
    content = filepath.read_text()

    if has_health_endpoint(content):
        return False  # Already has health endpoint

    module_name = get_module_name(filepath)

    # Check if MODULE_NAME is defined
    if "MODULE_NAME" in content:
        endpoint_code = HEALTH_ENDPOINT
    else:
        endpoint_code = HEALTH_ENDPOINT_INLINE.format(module=module_name)

    injection_point = find_injection_point(content)
    if injection_point == -1:
        print(f"  SKIP: No injection point found in {filepath}")
        return False

    # Inject the health endpoint
    new_content = content[:injection_point] + endpoint_code + "\n" + content[injection_point:]

    if dry_run:
        print(f"  DRY-RUN: Would add /health to {filepath.relative_to(PACKAGES_DIR)}")
    else:
        filepath.write_text(new_content)
        print(f"  ADDED: /health to {filepath.relative_to(PACKAGES_DIR)}")

    return True


def main():
    dry_run = "--dry-run" in sys.argv

    if dry_run:
        print("DRY RUN MODE - No files will be modified\n")

    # Find all main.py files in packages/*/api/
    api_files = list(PACKAGES_DIR.glob("secubox-*/api/main.py"))
    print(f"Found {len(api_files)} API modules\n")

    added = 0
    skipped = 0
    errors = 0

    for filepath in sorted(api_files):
        module = get_module_name(filepath)
        try:
            if add_health_endpoint(filepath, dry_run):
                added += 1
            else:
                content = filepath.read_text()
                if has_health_endpoint(content):
                    print(f"  EXISTS: /health already in {module}")
                skipped += 1
        except Exception as e:
            print(f"  ERROR: {module}: {e}")
            errors += 1

    print(f"\n{'DRY RUN ' if dry_run else ''}Summary:")
    print(f"  Added: {added}")
    print(f"  Skipped: {skipped}")
    print(f"  Errors: {errors}")


if __name__ == "__main__":
    main()
