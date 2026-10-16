# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2805 — l'API antirootkit lit le secret JWT dans /etc/secubox/secubox.conf (0640 secubox:secubox) : son compte dedie doit etre dans le groupe `secubox`.

Sans cela : « RuntimeError: jwt_secret is not configured » a chaque requete authentifiee, et la page /antirootkit/ affiche « API KO »."""
from pathlib import Path

UNITE = (Path(__file__).resolve().parents[1] / "debian" / "secubox-antirootkit.service").read_text()


def test_le_compte_dedie_est_dans_le_groupe_secubox():
    service = UNITE.split("[Service]", 1)[1]
    assert "User=secubox-antirootkit" in service
    assert "SupplementaryGroups=secubox" in [l.strip() for l in service.splitlines()]


def test_le_groupe_n_est_pas_le_groupe_principal():
    assert "Group=secubox-antirootkit" in UNITE   # on AJOUTE un groupe, on ne change pas l'identite du service
