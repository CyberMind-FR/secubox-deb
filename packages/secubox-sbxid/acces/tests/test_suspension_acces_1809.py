# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Lien d'entrée plafonné et suivi ; personne suspendue = porte fermée (#1809)."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

main = pytest.importorskip("api.main")
import jwt  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.profileur import Profileur  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_acces import DID, _remet_paire, form, paire, signe  # noqa: E402,F401


@pytest.fixture
def banc(tmp_path, monkeypatch):
    prof = Profileur(tmp_path / "demandes.json")
    monkeypatch.setattr(main, "_profileur", prof)
    monkeypatch.setattr(main, "_portier", None)
    monkeypatch.setattr(main, "_compteur", {})
    monkeypatch.setattr(main, "SBX_DB", tmp_path / "sbx.db")
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-1809")
    evts = []
    monkeypatch.setattr(main, "_emit_session_event", lambda e, u, d: evts.append((e, u, d)))
    monkeypatch.setattr(main.appareils, "inscris", lambda *a, **k: None)
    from secubox_core import auth as _auth
    monkeypatch.setattr(_auth, "get_config", lambda section="": {})
    return TestClient(main.app), prof, evts, tmp_path


def _admis(prof):
    priv, pub = paire()
    prof.demande(form(pub))
    prof.accepte(DID, par="gk2")
    return priv, pub


def test_le_lien_d_entree_est_plafonne_a_guest_et_suivi(banc):
    c, prof, evts, _ = banc
    _admis(prof)
    lien = main._liens.emet(DID)
    r = c.post("/session/entree", json={"entree": lien})
    assert r.status_code == 200
    jeton = r.cookies.get("secubox_session") or [v for k, v in r.headers.items() if k == "set-cookie"][0]
    jeton = jeton.split("secubox_session=", 1)[-1].split(";", 1)[0]
    p = jwt.decode(jeton, options={"verify_signature": False})
    assert p["plafond"] == "guest"
    assert p["jti"] in prof.demande_de(DID).jtis, "suivi : la révocation de l'appareil le coupe"


def _base(chemin: Path, pub: str, statut: str, revoque=None):
    from secubox_core import sbxid as S
    c = sqlite3.connect(chemin)
    c.executescript("CREATE TABLE sbx_users (user_uuid TEXT, status TEXT);"
                    "CREATE TABLE sbx_devices (did TEXT, user_uuid TEXT, revoked_at INTEGER);")
    c.execute("INSERT INTO sbx_users VALUES ('u1', ?)", (statut,))
    c.execute("INSERT INTO sbx_devices VALUES (?, 'u1', ?)", (S.did_appareil(pub), revoque))
    c.commit()
    c.close()


@pytest.mark.parametrize("statut,revoque,bloque", [
    ("active", None, False), ("suspended", None, True), ("active", 123, True)])
def test_une_personne_suspendue_n_ouvre_plus_de_session(banc, statut, revoque, bloque):
    c, prof, _, tmp = banc
    priv, pub = _admis(prof)
    _base(tmp / "sbx.db", pub, statut, revoque)
    jeton = prof.demande_de(DID).jeton
    r = c.get("/session/defi", params={"did": DID, "jeton": jeton})
    assert (r.status_code == 403) is bloque


def test_appareil_inconnu_de_la_base_n_est_pas_bloque(banc):
    c, prof, _, tmp = banc
    _admis(prof)
    assert not main._bloque_par_sbx(DID)                 # pas de base du tout
