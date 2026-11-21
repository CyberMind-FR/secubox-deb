# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration de DataScope : environnement > /etc/secubox/datascope.toml > défauts ; jamais bloquante."""
from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger("secubox-datascope")

CONFIG = Path("/etc/secubox/datascope.toml")

DEFAUT_BASE = Path("/var/lib/secubox-datascope/datascope.db")
DEFAUT_CACHE = Path("/var/cache/secubox/datascope")
DEFAUT_NAC_DB = Path("/var/lib/secubox/nac/devices.db")
DEFAUT_NETSTATS = Path("/var/lib/secubox/hub/netstats.json")
DEFAUT_MODULES = Path("/var/cache/secubox/health/modules.json")


@dataclass
class Config:
    base: Path
    cache: Path
    nac_db: Path
    netstats: Path
    modules: Path
    modules_perime_s: int = 300


def _section(brut: Dict[str, Any], nom: str) -> Dict[str, Any]:
    s = brut.get(nom)
    return s if isinstance(s, dict) else {}


def _chemin(env: str, valeur: Any, defaut: Path) -> Path:
    v = os.environ.get(env)
    if v:
        return Path(v)
    if isinstance(valeur, str) and valeur:
        return Path(valeur)
    return defaut


def charger(chemin_toml: Path = CONFIG) -> Config:
    """Environnement (tests), puis TOML, puis défauts ; un TOML absent ou cassé retombe sur les défauts."""
    try:
        brut = tomllib.loads(Path(chemin_toml).read_text(encoding="utf-8"))
    except FileNotFoundError:
        brut = {}
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        log.warning("datascope.toml illisible (%s) : valeurs par défaut", e)
        brut = {}
    st, so = _section(brut, "stockage"), _section(brut, "sources")
    perime = so.get("modules_perime_s", 300)
    if not isinstance(perime, int) or isinstance(perime, bool) or perime <= 0:
        perime = 300
    return Config(
        base=_chemin("SECUBOX_DATASCOPE_DB", st.get("base"), DEFAUT_BASE),
        cache=_chemin("SECUBOX_DATASCOPE_CACHE", st.get("cache"), DEFAUT_CACHE),
        nac_db=_chemin("SECUBOX_DATASCOPE_NAC_DB", so.get("nac_db"), DEFAUT_NAC_DB),
        netstats=_chemin("SECUBOX_DATASCOPE_NETSTATS", so.get("netstats"), DEFAUT_NETSTATS),
        modules=_chemin("SECUBOX_DATASCOPE_MODULES", so.get("modules"), DEFAUT_MODULES),
        modules_perime_s=perime,
    )
