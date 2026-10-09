# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Construit les deux applications du service Auto-Load (#2190) : la publique (socket Unix) et celle du tunnel (TCP 10.64.0.1:8470)."""
import os
from pathlib import Path

from autoload import jetons as J, tunnel as T
from api.main import creer_app


def construire():
    dossier = Path(os.environ.get("SECUBOX_AUTOLOAD_DOSSIER", T.DOSSIER_DEFAUT))
    cle_hub_pub = (dossier / "hub.pub").read_text(encoding="ascii").strip()          # posée par `autoloadctl tunnel-init`
    reg = J.Registre(dossier / "jetons.db", Path(os.environ.get("SECUBOX_AUTOLOAD_AUDIT", J.AUDIT_DEFAUT)))
    pairs = T.Pairs(dossier / "jetons.db")

    appliquer = T.appliquer_par_sudo
    return (creer_app(reg, pairs, cle_hub_pub, appliquer, portee="public"),
            creer_app(reg, pairs, cle_hub_pub, appliquer, portee="tunnel"))
