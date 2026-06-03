# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — wpa_supplicant pour 802.11s + WPA3-SAE (mode=5).
Le mot de passe SAE est résolu juste-à-temps via config.resolve_secret().
JAMAIS écrit dans un fichier de log.
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
from pathlib import Path

import jinja2

from .config import resolve_secret
from .models import Config

log = logging.getLogger("secubox.mesh")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "conf"


def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
        autoescape=False,
        keep_trailing_newline=True,
    )


def render(cfg: Config) -> str:
    """Rend conf/wpa_supplicant-mesh.conf.j2. Résout le secret en mémoire."""
    sae = resolve_secret(cfg.mesh.sae_password_ref)
    rendered = _env().get_template("wpa_supplicant-mesh.conf.j2").render(
        mesh=cfg.mesh.model_dump(),
        radio=cfg.radio.model_dump(),
        sae_password=sae,
    )
    # Defense in depth : si le secret se promène, le caller doit shred.
    return rendered


def write_conf(cfg: Config, out_path: Path = Path("/run/secubox/mesh/wpa_supplicant.conf")) -> Path:
    """Écrit la conf rendue (mode 0600). Réservée au bring-up."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = render(cfg)
    out_path.write_text(content)
    out_path.chmod(0o600)
    log.info("wrote %s (mode=0600, iface=%s)", out_path, cfg.radio.iface)
    return out_path
