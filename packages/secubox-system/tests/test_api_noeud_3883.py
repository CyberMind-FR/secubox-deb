# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3883 (ex #3824 de secubox-webos) — API du relais du nom de nœud dans secubox-system : `GET|POST
/api/v1/system/noeud/relais`, gardées par `require_jwt`, qui déposent une demande au programme root `secubox-noeud`
de secubox-core. Bout à bout avec le VRAI programme (banc de secubox-core) jusqu'à l'audit ; 404 si le cœur est trop
ancien ; rien n'est déposé sans jeton."""
import importlib.util
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

SYSTEM = Path(__file__).resolve().parents[1]
RACINE = SYSTEM.parents[1]
sys.path.insert(0, str(RACINE / "common"))

# Chargés par leur chemin : le nom de paquet `api` est aussi celui des composants testés dans la même session.
_spec = importlib.util.spec_from_file_location("noeud_router_3883", SYSTEM / "api" / "routers" / "noeud.py")
api_noeud = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_noeud)
_spec = importlib.util.spec_from_file_location("banc_noeud_coeur", RACINE / "packages/secubox-core/tests/banc_noeud.py")
_banc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_banc)
box_noeud = _banc.box_noeud   # fixture « box » : la box en miniature de secubox-core
DOM, conf, audits = _banc.DOM, _banc.conf, _banc.audits

CIBLE = ["192.168.1.200", 8000]


def test_routes_gardees_par_require_jwt_et_incluses():
    chemins = set()
    for r in api_noeud.router.routes:
        assert any(d.call is api_noeud.require_jwt for d in r.dependant.dependencies), r.path
        chemins |= {(m, r.path) for m in r.methods}
    assert chemins == {("GET", "/noeud/relais"), ("POST", "/noeud/relais")}
    main = (SYSTEM / "api" / "main.py").read_text()
    assert "from api.routers.noeud import router as noeud_router" in main and "app.include_router(noeud_router)" in main
    assert 'root_path="/api/v1/system"' in main
    corps = (SYSTEM / "api" / "routers" / "noeud.py").read_text().split('"""', 2)[2]
    assert "sudo" not in corps and "subprocess" not in corps
    assert str(api_noeud.DEMANDES) == "/run/secubox/noeud" and str(api_noeud.RESULTATS) == "/run/secubox/noeud-resultats"
    assert str(api_noeud.PROGRAMME) == "/usr/sbin/secubox-noeud"
    m = _banc.charger()
    assert (m.DEMANDES, m.RESULTATS) == (str(api_noeud.DEMANDES), str(api_noeud.RESULTATS))   # même contrat que le cœur


def test_401_sans_jeton_rien_n_est_depose(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-uniquement-0123456789abcdef")
    monkeypatch.setattr(api_noeud, "DEMANDES", tmp_path)
    app = FastAPI()
    app.include_router(api_noeud.router)
    c = TestClient(app)
    assert c.get("/noeud/relais").status_code == 401
    assert c.post("/noeud/relais", json={"actif": True}).status_code == 401
    assert list(tmp_path.iterdir()) == []


def test_404_si_secubox_core_trop_ancien(tmp_path, monkeypatch):
    monkeypatch.setattr(api_noeud, "PROGRAMME", tmp_path / "absent")
    monkeypatch.setattr(api_noeud, "DEMANDES", tmp_path)
    app = FastAPI()
    app.include_router(api_noeud.router)
    app.dependency_overrides[api_noeud.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    r = c.get("/noeud/relais")
    assert r.status_code == 404 and "secubox-core trop ancien" in r.json()["detail"]
    assert c.post("/noeud/relais", json={"actif": True}).status_code == 404
    assert list(tmp_path.iterdir()) == []


@pytest.fixture
def client(box, monkeypatch):
    """La box de gk2 (route reprise vers :8000), le dépôt, une « unité root » qui traite, l'API branchée dessus."""
    import json
    monkeypatch.setattr(box, "R", str(box.racine))              # pas de chown hors root
    (box.racine / "run/secubox").mkdir(parents=True)
    monkeypatch.setattr(box, "DEMANDES", str(box.racine / "run/secubox/noeud"))
    monkeypatch.setattr(box, "RESULTATS", str(box.racine / "run/secubox/noeud-resultats"))
    t = json.loads(Path(box.ROUTES).read_text())
    t[DOM] = CIBLE
    Path(box.ROUTES).write_text(json.dumps(t))
    box.sonde = 404
    assert box.appliquer() == 0 and box.prepare() == 0
    programme = box.racine / "secubox-noeud"
    programme.write_text("")
    monkeypatch.setattr(api_noeud, "PROGRAMME", programme)
    monkeypatch.setattr(api_noeud, "DEMANDES", Path(box.DEMANDES))
    monkeypatch.setattr(api_noeud, "RESULTATS", Path(box.RESULTATS))
    monkeypatch.setattr(api_noeud, "DELAI", 10.0)
    arret = threading.Event()

    def unite_root():                                             # ce que ferait secubox-noeud.path
        while not arret.is_set():
            if list(Path(box.DEMANDES).glob("*.demande")):
                box.traite()
            time.sleep(0.05)
    threading.Thread(target=unite_root, daemon=True).start()
    app = FastAPI()
    app.include_router(api_noeud.router)
    app.dependency_overrides[api_noeud.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(app)
    arret.set()


def test_api_bout_a_bout_jusqu_a_l_audit(client, box, monkeypatch):
    e = client.get("/noeud/relais").json()
    assert e["relais_api"] is False and e["cible"] == "192.168.1.200:8000" and e["domaine"] == DOM
    assert e["servis"] == ["/", "/_noeud/de3d.js", "/_noeud/polices/unbounded-latin.woff2", "/_noeud/polices/jetbrains-mono-latin.woff2", "/_noeud/sbx-dice.js", "/_noeud/dice/", "/api/v1/health"]
    r = client.post("/noeud/relais", json={"actif": True})
    assert r.status_code == 200 and r.json()["success"] and r.json()["relais_actif"] is True
    assert "proxy_pass http://192.168.1.200:8000;\n" in conf(box).split("location / {", 1)[1]
    assert Path(box.REGLAGES).name == "noeud.toml" and "relais_api = true" in Path(box.REGLAGES).read_text()
    a = audits(box)[-1]
    assert a["module"] == "noeud" and a["result"] == "ouvert" and "par admin" in a["detail"]
    r = client.post("/noeud/relais", json={"actif": False})
    assert r.status_code == 200 and r.json()["relais_actif"] is False
    assert audits(box)[-1]["result"] == "ferme"
    assert client.post("/noeud/relais", json={"actif": "oui"}).status_code == 422
    monkeypatch.setattr(box, "mot_de_passe_change", lambda: False)
    r = client.post("/noeud/relais", json={"actif": True})
    assert r.status_code == 409 and "mot de passe" in r.json()["detail"]
    assert audits(box)[-1]["result"] == "refus"
