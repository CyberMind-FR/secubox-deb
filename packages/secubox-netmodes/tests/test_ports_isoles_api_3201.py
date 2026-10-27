# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3201 — API : POST /ports/{port}/isoler et /rattacher (netmodesctl, sudo -n), anti-coupure avant le contrôleur,
et lecture « isolé » de /reseau/ports (même listage que les coupures : en échec, tout est inconnu, jamais « aucun »)."""
import subprocess
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, ports_api, reseau_api, reseau_lecture as lect, routeur_api  # noqa: E402

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402
from test_panneau_api_3190 import (  # noqa: E402,F401
    CTL, ETAT, FDB, POSTE, VOISINS, Systeme, attendre_fin, client, faux, pont,
)

AUTRE = {"X-Real-IP": "203.0.113.9"}


def test_isoler_anti_coupure_409(client, monkeypatch):
    s = faux(monkeypatch, [])
    r = client.post("/ports/lan1/isoler", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 409
    assert r.json()["detail"] == "vous perdriez votre propre accès (votre poste est derrière lan1)"
    assert s.sudo() == []                                       # contrôleur jamais appelé
    assert len(s.lectures()) == 2


def test_isoler_un_autre_port_autorise(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    r = client.post("/ports/lan2/isoler", json={"confirmer": "lan2"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200
    assert s.sudo() == [["sudo", "-n", CTL, "port-isoler", "lan2", "alice"]]


def test_isoler_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    r = client.post("/ports/lan2/isoler", json={"confirmer": "lan2"}, headers=AUTRE)
    assert r.status_code == 200
    assert s.sudo() == [["sudo", "-n", CTL, "port-isoler", "lan2", "alice"]]
    argv, kw = s.appels[-1]
    assert kw["timeout"] == ports_api.DELAI_PORT and kw["check"] is False and not kw.get("shell")


def test_rattacher_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    r = client.post("/ports/lan2/rattacher", json={"confirmer": "lan2"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200                                 # pas de garde anti-coupure : aucune lecture
    assert s.lectures() == [] and s.sudo() == [["sudo", "-n", CTL, "port-rattacher", "lan2", "alice"]]


@pytest.mark.parametrize("corps", [None, {}, {"confirmer": "lan1"}, {"confirmer": True}, ["lan2"], "lan2"])
def test_confirmation_requise(client, monkeypatch, corps):
    s = faux(monkeypatch, [])
    for verbe in ("isoler", "rattacher"):
        r = client.post(f"/ports/lan2/{verbe}", **({} if corps is None else {"json": corps}))
        assert r.status_code == 400 and '"confirmer": "lan2"' in r.json()["detail"], (corps, verbe)
    assert s.appels == []


@pytest.mark.parametrize("port", ["eth2", "br-lan", "lan4"])
def test_port_hors_liste_400(client, monkeypatch, port):
    s = faux(monkeypatch, [])
    for verbe in ("isoler", "rattacher", "couper", "retablir"):
        r = client.post(f"/ports/{port}/{verbe}", json={"confirmer": port}, headers=AUTRE)
        assert r.status_code == 400, (port, verbe)
        assert r.json()["detail"] == "port refusé : seuls lan0, lan1, lan2, lan3 sont actionnables"
    assert s.appels == []


def test_sans_jeton_401(monkeypatch, pont):
    main.app.dependency_overrides.clear()
    s = faux(monkeypatch, [])
    c = TestClient(main.app, base_url="http://testserver")
    for verbe in ("isoler", "rattacher"):
        assert c.post(f"/ports/lan2/{verbe}", json={"confirmer": "lan2"}).status_code == 401
    assert s.appels == []


def test_pendant_une_bascule_409(client, monkeypatch):
    s = faux(monkeypatch, [])
    monkeypatch.setattr(ports_api, "bascule_lancee", lambda: True)
    for verbe in ("isoler", "rattacher"):
        r = client.post(f"/ports/lan2/{verbe}", json={"confirmer": "lan2"}, headers=AUTRE)
        assert r.status_code == 409 and "bascule" in r.json()["detail"]
    assert s.appels == []


@pytest.mark.parametrize("code, http", [(3, 409), (4, 409), (2, 400), (1, 502)])
def test_codes_du_controleur(client, monkeypatch, code, http):
    faux(monkeypatch, [(code, {"erreur": "boum"})])
    r = client.post("/ports/lan2/isoler", json={"confirmer": "lan2"}, headers=AUTRE)
    assert r.status_code == http and r.json()["detail"]


def test_action_reussie_invalide_le_cache(client, monkeypatch):
    faux(monkeypatch, [(0, ETAT)])
    reseau_api._cache.update(t=1e18, valeur={"x": 1})
    client.post("/ports/lan2/rattacher", json={"confirmer": "lan2"})
    assert reseau_api._cache == {}


def test_restreint_expose_ports_isoles():
    assert "ports_isoles" in routeur_api.CLES_RESTREINTES and "ports_coupes" in routeur_api.CLES_RESTREINTES


# --- lecture -----------------------------------------------------------------------------------------------------------

def _fausse_json(argv):
    if argv == ["ip", "-j", "link"]:
        return [{"ifname": n, "flags": ["UP"], "master": "br-lan" if n.startswith("lan") else None}
                for n in ("lan0", "lan1", "lan2", "lan3", "eth2")]
    return []


@pytest.fixture
def lecture(monkeypatch, tmp_path):
    reseau_api.invalider()
    monkeypatch.setattr(reseau_api, "_json", _fausse_json)
    monkeypatch.setattr(reseau_api, "RESEAU_D", tmp_path)
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    yield TestClient(main.app, base_url="http://testserver"), tmp_path
    main.app.dependency_overrides.clear()
    reseau_api.invalider()


def test_isoles_regex():
    noms = ["04-secubox-port-lan2-isole.network", "04-secubox-port-lan1-coupe.network", "04-secubox-port-eth2-isole.network",
            "04-secubox-port-lan4-isole.network", "x04-secubox-port-lan0-isole.network"]
    assert reseau_api.ports_isoles(noms) == {"lan2"} and reseau_api.ports_coupes(noms) == {"lan1"}


def test_lecture_isole(lecture):
    c, d = lecture
    (d / "04-secubox-port-lan2-isole.network").write_text("")
    r = c.get("/reseau/ports")
    assert r.status_code == 200
    ports = {p["nom"]: p for p in r.json()["ports"]}
    assert ports["lan2"]["isole"] is True and ports["lan2"]["reseau_isole"] == "192.168.250.0/24"
    for n in ("lan0", "lan1", "lan3", "eth2"):
        assert ports[n]["isole"] is False and ports[n]["reseau_isole"] is None, n
    assert "isoles" not in r.json()["pannes"] and "coupes" not in r.json()["pannes"]


def test_lecture_listage_en_echec(lecture, monkeypatch):
    c, d = lecture
    monkeypatch.setattr(reseau_api, "RESEAU_D", d / "absent")
    r = c.get("/reseau/ports")
    ports = {p["nom"]: p for p in r.json()["ports"]}
    assert all(p["isole"] is None and p["coupe"] is None and p["reseau_isole"] is None for p in ports.values())
    assert {"coupes", "isoles"} <= set(r.json()["pannes"])


def test_lect_ports_isoles_param():
    ip_link = _fausse_json(["ip", "-j", "link"])
    p = {x["nom"]: x for x in lect.ports(ip_link, [], {}, set(), set(), {"lan0"})}
    assert p["lan0"]["isole"] is True and p["lan0"]["reseau_isole"] == "192.168.248.0/24"
    assert p["eth2"]["isole"] is False and p["eth2"]["reseau_isole"] is None
    p = {x["nom"]: x for x in lect.ports(ip_link, [], {}, set(), set(), None)}
    assert p["lan0"]["isole"] is None and p["eth2"]["isole"] is None
