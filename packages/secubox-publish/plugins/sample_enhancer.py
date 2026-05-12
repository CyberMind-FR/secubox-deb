# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Sample Plugin — ISP Home Publish Enhancer

This plugin demonstrates the module injection system for extending
publish capabilities with custom hooks.

To create your own plugin:
1. Create a .py file in /srv/secubox/modules/publish/plugins/
2. Define PLUGIN_INFO dict with metadata
3. Implement hook_* functions for desired extension points

Available hooks:
- hook_pre_upload(file, name) -> Dict
- hook_post_upload(name, path) -> Dict
- hook_pre_publish(name, content_type, path) -> Dict
- hook_post_publish(name, content_type, url) -> Dict
- hook_content_detect(path, files) -> Dict with optional "content_type" key
- hook_bundle_create(name, path) -> Dict
- hook_bundle_extract(name, path) -> Dict
"""

from pathlib import Path
from datetime import datetime

# Plugin metadata (required)
PLUGIN_INFO = {
    "name": "sample_enhancer",
    "version": "1.0.0",
    "description": "Sample plugin demonstrating ISP Home Publish hooks",
    "author": "CyberMind",
    "hooks": ["pre_upload", "post_publish", "content_detect"],
}


def hook_pre_upload(file=None, name=None, **kwargs):
    """Called before file upload is processed.

    Can be used to:
    - Validate file types
    - Check quotas
    - Log upload attempts
    """
    return {
        "enhancer_pre_upload": True,
        "timestamp": datetime.now().isoformat(),
    }


def hook_content_detect(path=None, files=None, **kwargs):
    """Called during content type detection.

    Can be used to:
    - Detect custom content types
    - Override default detection
    - Add framework-specific handling
    """
    if path and Path(path).exists():
        # Example: detect Next.js projects
        if any("next.config" in f for f in (files or [])):
            return {"content_type": "nextjs"}

        # Example: detect Astro projects
        if any("astro.config" in f for f in (files or [])):
            return {"content_type": "astro"}

    return {}


async def hook_post_publish(name=None, content_type=None, url=None, **kwargs):
    """Called after successful publish.

    Can be used to:
    - Send notifications
    - Update external systems
    - Trigger CI/CD pipelines
    - Generate documentation
    """
    return {
        "enhancer_post_publish": True,
        "published_at": datetime.now().isoformat(),
        "name": name,
        "type": content_type,
    }
