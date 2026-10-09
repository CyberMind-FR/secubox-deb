# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Construit les deux applications du service Auto-Load (#2190) : la publique (socket Unix) et celle du tunnel (TCP 10.64.0.1:8470)."""
import os
from pathlib import Path

from autoload import jetons as J, rapport as R, tunnel as T
from api.main import creer_app


def _courrier():
    """Le courrier du rapport final : actif seulement si /etc/secubox/autoload.toml porte [rapport] smtp_hote, smtp_port, expediteur."""
    import tomllib  # noqa: PLC0415
    try:
        with open(os.environ.get("SECUBOX_AUTOLOAD_CONFIG", "/etc/secubox/autoload.toml"), "rb") as f:
            c = tomllib.load(f).get("rapport", {})
        hote, port, exp = str(c["smtp_hote"]), int(c["smtp_port"]), str(c["expediteur"])
    except (OSError, KeyError, ValueError, TypeError):
        return None
    return lambda rap, email: R.envoyer(rap, email, hote, port, exp)


def construire():
    dossier = Path(os.environ.get("SECUBOX_AUTOLOAD_DOSSIER", T.DOSSIER_DEFAUT))
    cle_hub_pub = (dossier / "hub.pub").read_text(encoding="ascii").strip()          # posée par `autoloadctl tunnel-init`
    reg = J.Registre(dossier / "jetons.db", Path(os.environ.get("SECUBOX_AUTOLOAD_AUDIT", J.AUDIT_DEFAUT)))
    pairs = T.Pairs(dossier / "jetons.db")

    appliquer = T.appliquer_par_sudo
    courrier = _courrier()
    return (creer_app(reg, pairs, cle_hub_pub, appliquer, portee="public", courrier=courrier),
            creer_app(reg, pairs, cle_hub_pub, appliquer, portee="tunnel", courrier=courrier))
