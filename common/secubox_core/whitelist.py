# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""ToolBoX whitelist (#492) : map host/SNI -> bypass-reason + category.

YAML format (operator can override at /etc/secubox/toolbox/whitelist.yaml) :

    whitelist:
      - pattern: "*.push.apple.com"
        reason: cert-pinning, no MITM possible
        category: vendor-os
        quality_expected: A+
      - pattern: "signal.org"
        reason: E2E messenger, transport-only observation
        category: messaging-e2e
        quality_expected: A+

Patterns are fnmatch-style globs (Unix shell). Phase 4 will add regex/ASN/JA4 match.
"""
from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("secubox.whitelist")

BASELINE_PATH = Path("/usr/share/secubox/toolbox/whitelist-baseline.yaml")
OVERRIDE_PATH = Path("/etc/secubox/toolbox/whitelist.yaml")

_CACHE: dict | None = None
_CACHE_MTIME: float = 0.0


def _load_yaml(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        import yaml as _yaml
    except ImportError:
        log.warning("PyYAML unavailable, whitelist disabled")
        return []
    try:
        data = _yaml.safe_load(path.read_text()) or {}
        return data.get("whitelist", []) or []
    except Exception as e:
        log.warning("whitelist load failed (%s): %s", path, e)
        return []


def _refresh_cache() -> dict:
    """Hot-reload : combine baseline + override, re-read if either mtime changed."""
    global _CACHE, _CACHE_MTIME
    mtime = 0.0
    for p in (BASELINE_PATH, OVERRIDE_PATH):
        if p.exists():
            mtime = max(mtime, p.stat().st_mtime)
    if _CACHE is not None and mtime <= _CACHE_MTIME:
        return _CACHE
    entries = _load_yaml(BASELINE_PATH) + _load_yaml(OVERRIDE_PATH)
    # Compile : map pattern -> entry. Override wins on dup (last in list).
    compiled: dict[str, dict] = {}
    for e in entries:
        p = e.get("pattern", "").lower().strip()
        if p:
            compiled[p] = e
    _CACHE = {"entries": compiled, "count": len(compiled)}
    _CACHE_MTIME = mtime
    log.info("whitelist reloaded : %d entries", len(compiled))
    return _CACHE


def match(host: str) -> Optional[dict]:
    """Return the matching whitelist entry for a host, or None."""
    if not host:
        return None
    h = host.lower().strip()
    cache = _refresh_cache()
    for pattern, entry in cache["entries"].items():
        if fnmatch.fnmatch(h, pattern):
            return entry
    return None


def is_whitelisted(host: str) -> bool:
    return match(host) is not None


def stats() -> dict:
    """Returns {count, baseline_loaded, override_loaded}."""
    cache = _refresh_cache()
    return {
        "count": cache["count"],
        "baseline_loaded": BASELINE_PATH.exists(),
        "override_loaded": OVERRIDE_PATH.exists(),
    }
