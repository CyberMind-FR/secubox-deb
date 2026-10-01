# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Routes : retrouver sa demande par la clé, la renouveler (#1805)."""
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
from test_acces import DID, _remet_paire, form, paire, signe  # noqa: E402,F401


@pytest.fixture
def banc(tmp_path, monkeypatch):
    prof = Profileur(tmp_path / "demandes.json")
    monkeypatch.setattr(main, "_profileur", prof)
    monkeypatch.setattr(main, "_portier", None)
    monkeypatch.setattr(main, "_compteur_retrouvailles", {})
    monkeypatch.setattr(main, "_compteur", {})
    return TestClient(main.app), prof


def test_le_navigateur_retrouve_puis_renouvelle(banc, monkeypatch):
    c, prof = banc
    priv, pub = paire()
    r = c.post("/invitation/demande", json=form(pub))
    assert r.status_code == 200
    prof.refuse(DID, par="gk2")

    # Jeton de suivi perdu : la clé retrouve la demande.
    defi = c.get("/invitation/retrouver/defi", params={"did": DID}).json()["defi"]
    v = c.post("/invitation/retrouver", json={"did": DID, "defi": defi,
                                              "signature": signe(priv, bytes.fromhex(defi))}).json()
    assert v["etat"] == "refusee" and v["jeton"]

    # Trop tôt après le refus, puis possible.
    assert c.post("/invitation/renouveler", json={"did": DID, "jeton": v["jeton"]}).status_code == 429
    from api import profileur as P
    monkeypatch.setattr(P, "RENOUVELLEMENT_DELAI_S", 0)
    r = c.post("/invitation/renouveler", json={"did": DID, "jeton": v["jeton"]})
    assert r.status_code == 200 and r.json()["etat"] == "en_attente"
    assert len(prof.en_attente()) == 1


def test_mauvaise_signature_403_et_jeton_jamais_rendu(banc):
    c, _ = banc
    _, pub = paire()
    c.post("/invitation/demande", json=form(pub))
    voleur, _ = paire()
    defi = c.get("/invitation/retrouver/defi", params={"did": DID}).json()["defi"]
    r = c.post("/invitation/retrouver", json={"did": DID, "defi": defi,
                                              "signature": signe(voleur, bytes.fromhex(defi))})
    assert r.status_code == 403 and "jeton" not in r.text


def test_renouveler_mauvais_jeton_404(banc):
    c, _ = banc
    _, pub = paire()
    c.post("/invitation/demande", json=form(pub))
    assert c.post("/invitation/renouveler", json={"did": DID, "jeton": "x"}).status_code == 404


def test_cadence_des_retrouvailles(banc, monkeypatch):
    c, _ = banc
    monkeypatch.setattr(main, "RETROUVAILLES_PAR_IP", 2)
    for _ in range(2):
        assert c.get("/invitation/retrouver/defi", params={"did": DID}).status_code == 200
    assert c.get("/invitation/retrouver/defi", params={"did": DID}).status_code == 429
