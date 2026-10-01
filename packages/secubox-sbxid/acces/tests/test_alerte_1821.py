# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Une demande qui entre dans la file prévient l'administration (#1821)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

main = pytest.importorskip("api.main")
from fastapi.testclient import TestClient  # noqa: E402

from api.profileur import Profileur  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_acces import DID, _remet_paire, form, paire  # noqa: E402,F401


@pytest.fixture
def banc(tmp_path, monkeypatch):
    prof = Profileur(tmp_path / "demandes.json")
    monkeypatch.setattr(main, "_profileur", prof)
    monkeypatch.setattr(main, "_compteur", {})
    alertes = []
    monkeypatch.setattr(main, "_alerte_admin", lambda d, renouvelee=False: alertes.append((d.nom, renouvelee)))
    return TestClient(main.app), prof, alertes


def test_nouvelle_demande_alerte_une_fois(banc):
    c, prof, alertes = banc
    _, pub = paire()
    c.post("/invitation/demande", json=form(pub))
    c.post("/invitation/demande", json=form(pub))          # même demande, encore en attente
    assert alertes == [("Gérald", False)]


def test_demande_renouvelee_alerte(banc, monkeypatch):
    c, prof, alertes = banc
    _, pub = paire()
    c.post("/invitation/demande", json=form(pub))
    prof.refuse(DID, par="gk2")
    from api import profileur as P
    monkeypatch.setattr(P, "RENOUVELLEMENT_DELAI_S", 0)
    c.post("/invitation/demande", json=form(pub))
    assert alertes[-1] == ("Gérald", True)


def test_alerte_envoyee_coupable_et_plafonnee(tmp_path, monkeypatch):
    import importlib
    m = importlib.reload(main)                              # vrai _alerte_admin
    envois = []
    from secubox_core import courriel
    monkeypatch.setattr(courriel, "envoie", lambda dest, sujet, corps: envois.append((dest, sujet, corps)))

    class _Fil:
        def __init__(self, target, **k):
            self.t = target

        def start(self):
            self.t()
    import threading
    monkeypatch.setattr(threading, "Thread", _Fil)
    monkeypatch.setattr(m, "_destinataire_alerte", lambda: "gk2@secubox.in")
    monkeypatch.setattr(m, "_alertes", [])
    monkeypatch.setattr(m, "ALERTES_PAR_HEURE", 2)

    class D:
        nom, appareil, empreinte, message, email = "Ana", "Pixel", "aaaa bbbb", "bonjour", ""
    for _ in range(3):
        m._alerte_admin(D())
    assert len(envois) == 2, "plafond par heure"
    assert envois[0][0] == "gk2@secubox.in" and "Ana" in envois[0][1] and "/identite/#admin" in envois[0][2]
    monkeypatch.setattr(m, "_destinataire_alerte", lambda: None)
    monkeypatch.setattr(m, "_alertes", [])
    m._alerte_admin(D())
    assert len(envois) == 2, "alerte coupée : rien n'est envoyé"
