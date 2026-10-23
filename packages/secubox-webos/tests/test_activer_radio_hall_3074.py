# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3074 — une demande de LECTURE (media.play) pour un service sans cadre ouvert ouvre son lecteur /micro ; les
autres actions n'ouvrent rien."""
import re
from pathlib import Path

HALL = (Path(__file__).resolve().parents[1] / "www" / "hall" / "index.html").read_text()


def test_seule_la_lecture_ouvre_un_lecteur():
    appels = re.findall(r"ouvrePourLire\(", HALL)
    assert len(appels) == 2                        # la définition et un seul appel
    assert "if(!ok && req.action==='media.play') ok=ouvrePourLire(req.service, cap.message);" in HALL


def test_le_lecteur_vient_de_la_vue_micro_declaree():
    corps = HALL.split("function ouvrePourLire", 1)[1].split("window.sbxExecuteAction", 1)[0]
    assert "a.micro" in corps and "FEATURED" in corps and "ouvreLecteurViewer" in corps
    assert "new URL(f.src).origin" in corps and "'*'" not in corps   # jamais un postMessage à toute origine
