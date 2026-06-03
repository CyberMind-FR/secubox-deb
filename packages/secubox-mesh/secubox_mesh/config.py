# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — loader TOML + résolution secrets.
Spec : CM-MESH-MPCIE-2026-06 §2 (garde-fous), §4 (schéma TOML).
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from .models import Config

log = logging.getLogger("secubox.mesh")
CONFIG_PATH = Path("/etc/secubox/mesh.toml")


def load_config(path: Path = CONFIG_PATH) -> Config:
    """Charge /etc/secubox/mesh.toml. Lecture seule au runtime."""
    with path.open("rb") as f:
        raw = tomllib.load(f)
    cfg = Config.model_validate(raw)

    # Garde-fous (§2)
    if cfg.opad.reactive:
        log.warning(
            "OPAD reactive=true — réaction RF active, hors posture passive par défaut"
        )
    log.warning(
        "SAE-mesh: maturité dépendante du chipset (%s) — POINT OUVERT CSPN",
        cfg.radio.driver,
    )
    return cfg


def resolve_secret(ref: str) -> str:
    """
    Résout un sae_password_ref TOML. Schemes supportés :
      - file:///path   → contenu fichier, EXIGE chmod 0600
      - vault://...    → backend coffre (à implémenter)
    Jamais de retour de secret écrit dans un log.
    """
    u = urlparse(ref)
    if u.scheme == "file":
        p = Path(u.path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise PermissionError(
                f"{p}: droits trop ouverts (mode={oct(st.st_mode & 0o777)}), exiger 0600"
            )
        return p.read_text().strip()
    if u.scheme == "vault":
        raise NotImplementedError("backend vault:// à implémenter")
    raise ValueError(f"sae_password_ref non supporté: {ref}")
