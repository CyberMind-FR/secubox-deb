# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""TOML loader + resolve_secret pour secubox-toolbox."""
from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from .models import Config

log = logging.getLogger("secubox.toolbox")
CONFIG_PATH = Path("/etc/secubox/toolbox.toml")


def load_config(path: Path = CONFIG_PATH) -> Config:
    with path.open("rb") as f:
        raw = tomllib.load(f)
    cfg = Config.model_validate(raw)
    if cfg.r2.enabled:
        log.warning("R2 (TLS-break) ENABLED — opt-in CSPN, vérifier consentement par MAC.")
    return cfg


def resolve_secret(ref: str) -> str:
    u = urlparse(ref)
    if u.scheme == "file":
        p = Path(u.path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise PermissionError(
                f"{p}: droits trop ouverts (mode={oct(st.st_mode & 0o777)}), exiger 0600/0640"
            )
        return p.read_text().strip()
    raise ValueError(f"secret scheme unsupported: {ref}")
