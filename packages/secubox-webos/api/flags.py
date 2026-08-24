# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — chargement des feature flags (webos.toml)."""
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # 3.10 fallback
    import tomli as tomllib


def load_flags(path: str = "/etc/secubox/webos.toml") -> dict:
    data = {}
    try:
        data = tomllib.loads(Path(path).read_text()).get("webos", {})
    except Exception:
        data = {}
    return {
        "enabled": bool(data.get("enabled", False)),
        "registry_enabled": bool(data.get("registry_enabled", True)),
    }
