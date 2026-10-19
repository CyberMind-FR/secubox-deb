# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2877 — secubox-auth fonctionne SANS secubox-annuaire (profil minimal).

L'annuaire ne sert qu'à la délégation d'accès : ses modules sont importés à la demande (api/delegation.py), jamais au démarrage. Le paquet ne l'exige donc plus
(Recommends), et son absence donne un 501 explicite sur les routes de délégation, pas une 500."""
import re
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

PKG = Path(__file__).resolve().parents[1]


def _champ(nom):
    ctl = (PKG / "debian" / "control").read_text(encoding="utf-8")
    ctl = re.sub(r"(?m)^#.*\n", "", ctl)
    m = re.search(rf"(?m)^{nom}:((?:.*\n)(?: .*\n)*)", ctl)
    return m.group(1) if m else ""


def test_le_paquet_ne_exige_plus_annuaire():
    assert "secubox-annuaire" not in _champ("Depends")
    assert "secubox-annuaire" in _champ("Recommends")


def test_sans_annuaire_la_delegation_repond_501(monkeypatch, tmp_path):
    sys.path.insert(0, str(PKG))
    from api import delegation as D
    monkeypatch.setattr(D, "ANNUAIRE_LIB", str(tmp_path / "absent"))
    for nom in [n for n in sys.modules if n == "annuaire" or n.startswith("annuaire.")]:
        monkeypatch.delitem(sys.modules, nom, raising=False)
    monkeypatch.setattr(sys, "path", [p for p in sys.path if "annuaire" not in p])
    with pytest.raises(HTTPException) as e:
        D.annuaire()
    assert e.value.status_code == 501 and "annuaire" in e.value.detail.lower()
