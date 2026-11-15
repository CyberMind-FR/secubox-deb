# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3734 : routes de la mémoire des leurres — lecture en JWT (mots de passe en clair), gestes de ban audités."""
import json
import time

import pytest

from .test_gestes_ia_3716 import _importer_waf
from .test_leurres_memoire_3734 import ligne


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import leurres as lr, leurres_memoire as lm
    from secubox_core.auth import require_jwt
    journal = tmp_path / "waf-threats.log"
    t = int(time.time()) - 60
    journal.write_text(
        ligne("203.0.113.24", "telnet", t, "force-brute", "telnet", [("root", "xc3511"), ("admin", "xc3511")])
        + ligne("198.51.100.7", "vnc", t + 1, "sondeur", "vnc client RFB 003.003")
        + ligne("local", "telnet", t + 2, "force-brute", "telnet", [("a", "b")], action="detect"))
    gestes = []
    monkeypatch.setattr(lr, "_memoire", lm.Memoire(tmp_path / "leurres.db", journal))
    monkeypatch.setitem(lr._config, "bans", lambda: [{"ip": "198.51.100.7", "expires_in": 3600}])
    monkeypatch.setitem(lr._config, "ban", lambda ip, duree: (gestes.append(("ban", ip, duree)) or (True, "ok")))
    monkeypatch.setitem(lr._config, "unban", lambda ip: (gestes.append(("unban", ip)) or (True, "ok")))
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    client = TestClient(waf.app)
    client.gestes, client.audit, client.waf, client.garde = gestes, tmp_path / "audit.log", waf, require_jwt
    waf.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        yield client
    finally:
        waf.app.dependency_overrides.clear()


def test_lecture_refusee_sans_jwt(c):
    c.waf.app.dependency_overrides.clear()
    for route in ("resume", "attaquants", "dictionnaire", "rejeux", "attaquant/203.0.113.24"):
        assert c.get("/leurres/" + route).status_code in (401, 403), route
    assert c.post("/leurres/ban", json={"ip": "203.0.113.24", "duree": "24h"}).status_code in (401, 403)


def test_resume_et_attaquants_avec_etat_du_ban(c):
    r = c.get("/leurres/resume").json()
    assert r["attaquants"] == 2 and r["couples"] == 3 and r["bans_actifs"] == 1 and r["rejeux"] == 1
    a = {x["ip"]: x for x in c.get("/leurres/attaquants").json()["attaquants"]}
    assert a["198.51.100.7"]["ban"] == {"actif": True, "expire_dans": 3600}
    assert a["203.0.113.24"]["ban"] == {"actif": False, "expire_dans": None}
    assert a["local"]["ban"] is None                     # LAN : jamais bannissable
    assert a["203.0.113.24"]["essais"][0] == {"compte": "root", "mot_de_passe": "xc3511"}
    assert [x["ip"] for x in c.get("/leurres/attaquants?profil=sondeur").json()["attaquants"]] == ["198.51.100.7"]


def test_fiche_dictionnaire_rejeux(c):
    assert len(c.get("/leurres/attaquant/203.0.113.24").json()["visites"]) == 1
    assert c.get("/leurres/dictionnaire").json()["mots_de_passe"][0]["mot_de_passe"] == "xc3511"
    assert c.get("/leurres/rejeux").json()["mot_de_passe_plusieurs_comptes"][0]["comptes"] == ["admin", "root"]


def test_ban_et_levee_audites(c):
    assert c.post("/leurres/ban", json={"ip": "203.0.113.24", "duree": "24h"}).json()["success"] is True
    assert c.post("/leurres/unban", json={"ip": "198.51.100.7"}).json()["success"] is True
    assert c.gestes == [("ban", "203.0.113.24", "24h"), ("unban", "198.51.100.7")]
    actions = [json.loads(x)["action"] for x in c.audit.read_text().splitlines()]
    assert actions == ["leurre-ban", "leurre-unban"]
    assert json.loads(c.audit.read_text().splitlines()[0])["by"] == "admin"


@pytest.mark.parametrize("corps", [{"ip": "203.0.113.24", "duree": "30d"}, {"ip": "203.0.113.24", "duree": "permanent"},
                                   {"ip": "pas-une-adresse", "duree": "4h"}])
def test_ban_formes_refusees(c, corps):
    assert c.post("/leurres/ban", json=corps).status_code == 422 and c.gestes == []


@pytest.mark.parametrize("ip", ["local", "192.168.1.9", "203.0.113.99"])
def test_ban_hors_memoire_ou_prive_refuse(c, ip):
    r = c.post("/leurres/ban", json={"ip": ip, "duree": "4h"})
    assert r.status_code in (404, 409, 422) and c.gestes == []


def test_echec_de_wafctl_propage_et_audite(c, monkeypatch):
    from api import leurres as lr
    monkeypatch.setitem(lr._config, "ban", lambda ip, duree: (False, "protégée"))
    r = c.post("/leurres/ban", json={"ip": "203.0.113.24", "duree": "4h"})
    assert r.status_code == 502
    assert json.loads(c.audit.read_text().splitlines()[-1])["action"] == "leurre-ban-echec"


def test_page_et_onglet():
    from pathlib import Path
    www = Path(__file__).resolve().parents[1] / "www" / "waf"
    page = (www / "leurres.html").read_text(encoding="utf-8")
    assert "innerHTML" not in page.split("<script>", 1)[1]      # textes choisis par l'attaquant : textContent seulement
    assert "/api/v1/waf/leurres/" in page and "sbx_token" in page
    index = (www / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="decoys">Leurres<' in index and "decoys: 'leurres'" in index


def test_prolonger_leve_puis_repose(c):
    """`nft add element` ne change pas l'échéance d'un élément présent : prolonger = lever puis bannir."""
    assert c.post("/leurres/ban", json={"ip": "198.51.100.7", "duree": "7d"}).status_code == 200
    assert c.gestes == [("unban", "198.51.100.7"), ("ban", "198.51.100.7", "7d")]


def test_bans_illisibles_inconnu_jamais_non_banni(c, monkeypatch):
    from api import leurres as lr

    def muet():
        raise RuntimeError("nft muet")
    monkeypatch.setitem(lr._config, "bans", muet)
    assert c.get("/leurres/resume").json()["bans_actifs"] is None
    a = {x["ip"]: x for x in c.get("/leurres/attaquants").json()["attaquants"]}
    assert a["203.0.113.24"]["ban"] == {"actif": None, "expire_dans": None}


def test_base_sans_entree_d_acl_nommee(c, tmp_path):
    import os
    c.get("/leurres/resume")
    try:
        os.getxattr(tmp_path / "leurres.db", "system.posix_acl_access")
    except OSError:
        return
    raise AssertionError("la base porte une ACL d'accès")
