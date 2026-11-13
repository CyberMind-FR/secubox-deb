# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3704 : /portal/ disait « No token » à un administrateur connecté — le portail ne lisait que son ancien cookie et ses
sessions en mémoire. Vérification par secubox_core.auth (Bearer ou cookie secubox_session), sessions lues dans le
registre partagé de secubox-auth, révocation par l'événement de session."""
import json
import sys
import time
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PAQUET.parents[1] / "common"), str(PAQUET)]

from api import main as m  # noqa: E402

VALIDES = {"bon-admin": {"sub": "gk2", "jti": "a1", "role": "admin", "exp": 9_999_999_999},
           "bon-cookie": {"sub": "gek", "jti": "b2", "exp": 9_999_999_999}}


class Req:
    def __init__(self, entete=None, cookies=None):
        self.headers = {"authorization": entete} if entete else {}
        self.cookies = cookies or {}


@pytest.fixture
def registre(tmp_path, monkeypatch):
    f = tmp_path / "sessions.json"
    maintenant = time.time()
    f.write_text(json.dumps([
        {"id": "a1", "username": "gk2", "type": "jwt", "created": "2026-11-13T02:27:51", "expires": maintenant + 3600,
         "ip": "192.168.1.3", "user_agent": "Firefox"},
        {"id": "b2", "username": "gek", "type": "jwt", "created": "2026-11-13T03:30:15", "expires": maintenant + 3600,
         "ip": "192.168.1.3", "user_agent": "Firefox"},
        {"id": "c3", "username": "vieux", "type": "jwt", "created": "2026-11-01T00:00:00", "expires": maintenant - 10,
         "ip": "x", "user_agent": "y"},
    ]))
    monkeypatch.setattr(m._registre, "_path", lambda: f)
    monkeypatch.setattr(m, "_validate_token", lambda t: VALIDES.get(t))
    monkeypatch.setattr(m, "est_admin_reel", lambda p: p.get("role") == "admin")
    monkeypatch.setattr(m, "_role_du_compte", lambda nom: "admin" if nom == "gk2" else "user")
    return f


def test_sessions_partagees_sans_identifiant_ni_session_echue(registre):
    s = m._sessions_partagees()
    assert [x["username"] for x in s] == ["gk2", "gek"]
    assert all("id" not in x and "jti" not in x for x in s)


@pytest.mark.parametrize("req, nom", [
    (Req(entete="Bearer bon-admin"), "gk2"),
    (Req(cookies={"secubox_session": "bon-cookie"}), "gek"),
    (Req(entete="Bearer faux", cookies={"secubox_session": "bon-cookie"}), "gek"),   # un Bearer périmé ne masque pas le cookie
])
def test_session_reconnue_par_jeton_ou_cookie(registre, req, nom):
    assert m._payload_requete(req)["sub"] == nom


def test_verify_administrateur_connecte(registre):
    import asyncio
    r = asyncio.run(m.verify(Req(entete="Bearer bon-admin")))
    assert r["valid"] is True and r["username"] == "gk2" and r["role"] == "admin"
    assert r["session"]["ip"] == "192.168.1.3"


def test_verify_sans_session(registre):
    import asyncio
    r = asyncio.run(m.verify(Req()))
    assert r["valid"] is False and "No token" not in r["error"]


def test_liste_des_sessions_du_registre(registre):
    import asyncio
    r = asyncio.run(m.sessions(user={"sub": "gk2"}))
    assert r["count"] == 2 and {(x["username"], x["role"]) for x in r["sessions"]} == {("gk2", "admin"), ("gek", "user")}


def test_revocation_par_l_evenement_de_session(registre, monkeypatch):
    import asyncio
    emis = []
    monkeypatch.setattr(m._registre, "jtis_du_compte", lambda nom: ["b2"] if nom == "gek" else [])
    monkeypatch.setattr(m, "_emit_session_event", lambda ev, nom, d: emis.append((ev, nom, d)))
    monkeypatch.setattr(m, "_record_event", lambda *a, **k: None)
    r = asyncio.run(m.revoke_session("gek", user={"sub": "gk2"}))
    assert r == {"success": True, "revoked": "gek", "count": 1}
    assert emis == [("sessions_coupees", "gek", {"jtis": ["b2"], "motif": "revocation_portail", "par": "gk2"})]
    assert asyncio.run(m.revoke_session("personne", user={"sub": "gk2"}))["success"] is False


def test_routes_d_administration_gardees_par_require_jwt():
    gardes = {r.path: [d.call for d in r.dependant.dependencies] for r in m.router.routes if hasattr(r, "dependant")}
    assert m.require_jwt in gardes["/sessions"]
    assert m.require_jwt in gardes["/sessions/{username}"]
