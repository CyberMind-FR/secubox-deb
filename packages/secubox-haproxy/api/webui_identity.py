"""
SecuBox-Deb :: webui_identity
CyberMind — https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Parses /etc/default/secubox and exposes the canonical admin URL + regex.
"""
import re
import shlex
from pathlib import Path
from functools import lru_cache

DEFAULTS_FILE = Path("/etc/default/secubox")


@lru_cache(maxsize=1)
def _parse_defaults() -> dict:
    out: dict = {}
    if not DEFAULTS_FILE.exists():
        return out
    for line in DEFAULTS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
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
