# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: webui_identity
CyberMind — https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Parses /etc/default/secubox and exposes the canonical admin URL + regex.
"""
import logging
import re
import shlex
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

DEFAULTS_FILE = Path("/etc/default/secubox")


@lru_cache(maxsize=1)
def _parse_defaults() -> dict:
    """Parse /etc/default/secubox into a dict of KEY=value pairs.

    Returns an empty dict on any read failure (caller surfaces the
    missing-HOSTNAME case as ValueError via get_identity()).
    """
    out: dict = {}
    if not DEFAULTS_FILE.exists():
        return out
    try:
        content = DEFAULTS_FILE.read_text()
    except OSError as e:
        logger.warning("cannot read %s: %s", DEFAULTS_FILE, e)
        return out
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # shlex.split handles quoted values; unquoted multi-word
        # values keep only the first token (by design).
        parts = shlex.split(v) if v else []
        out[k.strip()] = parts[0] if parts else ""
    return out


def get_identity() -> dict:
    """Return canonical board identity.

    Raises:
        ValueError: if SECUBOX_HOSTNAME is not set.
    """
    cfg = _parse_defaults()
    host = cfg.get("SECUBOX_HOSTNAME", "")
    suffix = cfg.get("SECUBOX_DOMAIN_SUFFIX", "secubox.in")
    if not host:
        raise ValueError(
            "SECUBOX_HOSTNAME not set in /etc/default/secubox"
        )
    admin = f"admin.{host}.{suffix}"
    regex = "^" + re.escape(admin) + "$"
    return {
        "hostname": host,
        "domain_suffix": suffix,
        "admin_domain": admin,
        "regex": regex,
    }


def invalidate_cache() -> None:
    """Drop the LRU cache so the next get_identity() re-reads the file."""
    _parse_defaults.cache_clear()
