# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: host_app classifier

Maps a hostname to a (category, app, emoji) triplet for banner injection
and DPI reports. Mirror of packages/secubox-toolbox/secubox_toolbox/dpi_class.py
kept here so packages that depend on secubox-core (cookies, dpi, soc) can
import classify_host directly without pulling the whole toolbox.

Phase 6.L (#496) : extended from 57 to 147 patterns covering streaming,
social, messaging E2E, search, cloud, dev, banking FR/intl, email, Apple,
Tor/VPN, news FR/intl, Wikipedia, AI/LLM, e-commerce, travel/SNCF,
gouv.fr, productivity, maps, gaming, crypto exchanges, ads/tracking,
APM monitoring, and CDN/cloud infra.
"""
from __future__ import annotations

import re

# Single source of truth : import the pattern list from secubox_toolbox.dpi_class
# at runtime when available, so toolbox edits propagate automatically.
# Falls back to a static copy here when secubox_toolbox isn't on the path.
try:
    import sys as _sys
    _sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox.dpi_class import APP_PATTERNS, CATEGORY_EMOJI
    from secubox_toolbox.dpi_class import classify_host, analyze_hosts  # noqa: F401
    _SOURCE = "secubox_toolbox.dpi_class"
except ImportError:
    # Static fallback : minimal pattern set. The full list lives in
    # secubox-toolbox. Keep this list short — it's just a smoke test
    # for environments where toolbox isn't installed.
    APP_PATTERNS = [
        (re.compile(r"(^|\.)youtube\.com$|googlevideo\.com$"), "streaming", "YouTube", "📺"),
        (re.compile(r"(^|\.)netflix\.com$"),                   "streaming", "Netflix", "🎬"),
        (re.compile(r"(^|\.)facebook\.com$"),                  "social", "Facebook", "👥"),
        (re.compile(r"(^|\.)wikipedia\.org$"),                 "knowledge", "Wikipedia", "📚"),
        (re.compile(r"(^|\.)google\.[a-z.]+$"),                "search", "Google", "🔍"),
        (re.compile(r"(^|\.)github\.com$"),                    "dev", "GitHub", "🐙"),
        (re.compile(r"(^|\.)signal\.org$"),                    "messaging-e2e", "Signal", "🔒"),
    ]
    CATEGORY_EMOJI = {
        "streaming": "📺", "social": "👥", "messaging-e2e": "🔒",
        "messaging": "💬", "search": "🔍", "knowledge": "📚",
        "dev": "💻", "other": "❔",
    }
    _SOURCE = "host_app.fallback"

    def classify_host(host: str) -> dict:
        if not host:
            return {"category": "other", "app": "?", "emoji": "❔"}
        h = host.lower()
        for pattern, category, app, emoji in APP_PATTERNS:
            if pattern.search(h):
                return {"category": category, "app": app, "emoji": emoji}
        return {"category": "other", "app": "?", "emoji": "❔"}

    def analyze_hosts(hosts):
        return {"top_apps": [], "by_category": {}, "category_emoji": CATEGORY_EMOJI}
