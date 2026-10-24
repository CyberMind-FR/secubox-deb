# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — chargement des feature flags (webos.toml)."""
import logging
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # 3.10 fallback
    import tomli as tomllib

logger = logging.getLogger(__name__)


def load_flags(path: str = "/etc/secubox/webos.toml") -> dict:
    data = {}
    try:
        data = tomllib.loads(Path(path).read_text()).get("webos", {})
    except FileNotFoundError:
        pass
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("webos.toml illisible (%s) : flags par défaut", exc)
    return {
        "enabled": bool(data.get("enabled", False)),
        "registry_enabled": bool(data.get("registry_enabled", True)),
        # Hall v2 (vue maître Aurora) par défaut (#3115) ; « hall_v2 = false » dans webos.toml reste le retour arrière.
        "hall_v2": bool(data.get("hall_v2", True)),
    }
