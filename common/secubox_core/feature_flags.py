# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox feature-flag reader. Single source of truth for runtime toggles."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Union

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

DEFAULT_PATH = Path("/etc/secubox/users.feature_flags.toml")

DEFAULTS: Dict[str, Dict[str, Any]] = {
    "auth": {
        "enforce_v2": False,
        "require_totp_for_admin": True,
    },
}

log = logging.getLogger("secubox.feature_flags")


def load(path: Union[Path, str, None] = None) -> Dict[str, Dict[str, Any]]:
    """Return defaults merged with values from `path` (TOML).

    Missing file or parse errors → defaults are returned (logged WARNING).
    """
    p = Path(path) if path is not None else DEFAULT_PATH
    merged = {k: dict(v) for k, v in DEFAULTS.items()}
    if not p.exists():
        return merged
    try:
        with p.open("rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        log.warning("feature_flags: could not parse %s (%s); using defaults", p, exc)
        return merged
    for section, overrides in (data or {}).items():
        if section not in merged or not isinstance(overrides, dict):
            continue
        for key, value in overrides.items():
            if key in merged[section]:
                merged[section][key] = value
    return merged
