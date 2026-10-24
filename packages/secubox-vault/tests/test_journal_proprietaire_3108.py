# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3108 — le service du Coffre remet son journal à son compte à chaque démarrage.

gk2, 2026-10-24 : ouverture en HTTP 500 (PermissionError sur /var/log/secubox/coffre.journal, re-chowné secubox:secubox
au démarrage alors que le service tourne sous secubox-coffre). Le postinst corrige à l'installation seulement."""
import configparser
from pathlib import Path

UNITE = Path(__file__).resolve().parents[1] / "debian" / "secubox-vault.service"


def _pre() -> list:
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    lignes = []
    for l in UNITE.read_text().splitlines():
        if l.startswith("ExecStartPre="):
            lignes.append(l.split("=", 1)[1])
    return lignes


def test_le_journal_est_rendu_au_compte_du_service_avant_chaque_demarrage():
    pre = " | ".join(_pre())
    assert "+/bin/chown secubox-coffre:secubox /var/log/secubox/coffre.journal" in pre
    assert "+/bin/chmod 0640 /var/log/secubox/coffre.journal" in pre


def test_le_journal_absent_est_cree_sans_bloquer_le_demarrage():
    # chown/chmod échouent sur un fichier absent : la création passe avant, et rien ne doit empêcher le démarrage
    pre = _pre()
    i_cree = next(i for i, l in enumerate(pre) if "coffre.journal" in l and ("touch" in l or "install" in l))
    i_chown = next(i for i, l in enumerate(pre) if l.startswith("+/bin/chown") and "coffre.journal" in l)
    assert i_cree < i_chown
