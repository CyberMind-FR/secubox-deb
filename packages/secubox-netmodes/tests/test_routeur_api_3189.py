# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — routes /routeur : appel du contrôleur par sudo, codes d'erreur, anciens chemins netplan refusés sur MOCHAbin."""
import ast
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, routeur_api  # noqa: E402

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

CONFIG = {"adresse": "192.168.77.1/24", "dhcp_debut": "192.168.77.100", "dhcp_fin": "192.168.77.199"}
ETAT_LAN = {"etat": "actif", "config": {}, "minuteur_actif": False, "dhcp_actif": True, "adresses_pont": ["192.168.42.1/24"]}


class Faux:
    def __init__(self, reponses):
        self.reponses = list(reponses)
        self.appels = []

    def __call__(self, argv, **kw):
        self.appels.append((argv, kw))
        r = self.reponses.pop(0)
        if isinstance(r, Exception):
            raise r
        code, sortie = r
        return subprocess.CompletedProcess(argv, code, stdout=sortie if isinstance(sortie, str) else json.dumps(sortie), stderr="")


@pytest.fixture
def client(monkeypatch):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "alice"}
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    monkeypatch.setattr(routeur_api, "est_mochabin", lambda: False)
    yield TestClient(main.app, base_url="http://testserver")
    main.app.dependency_overrides.clear()


def _faux(monkeypatch, reponses):
    f = Faux(reponses)
    monkeypatch.setattr(routeur_api.subprocess, "run", f)
    return f


def test_appliquer_sans_mot_de_confirmation_400(client, monkeypatch):
    f = _faux(monkeypatch, [])
    assert client.post("/routeur/appliquer", json=CONFIG).status_code == 400
    assert client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "oui"}).status_code == 400
    assert f.appels == []


def test_appliquer_transmet_json_et_acteur(client, monkeypatch):
    f = _faux(monkeypatch, [(0, ETAT_LAN), (0, {"etat": "en_attente"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    assert r.status_code == 200 and r.json()["etat"] == "en_attente"
    assert f.appels[0][0] == ["sudo", "-n", "/usr/sbin/netmodesctl", "routeur-etat"]
    argv, kw = f.appels[-1]
    assert argv == ["sudo", "-n", "/usr/sbin/netmodesctl", "routeur-appliquer", "alice"]
    assert json.loads(kw["input"]) == CONFIG and kw["timeout"] == 150 and kw["check"] is False


def test_refus_controleur_409(client, monkeypatch):
    _faux(monkeypatch, [(0, ETAT_LAN), (3, {"erreur": "réseau interdit"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    assert r.status_code == 409 and r.json()["detail"] == "réseau interdit"


def test_occupe_409(client, monkeypatch):
    _faux(monkeypatch, [(0, ETAT_LAN), (4, {"erreur": "x"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    assert r.status_code == 409 and r.json()["detail"] == "une application est déjà en cours"


def test_autres_codes(client, monkeypatch):
    _faux(monkeypatch, [(2, {"erreur": "acteur"})])
    assert client.post("/routeur/confirmer").status_code == 400
    _faux(monkeypatch, [(1, {"erreur": "boum"})])
    r = client.post("/routeur/confirmer")
    assert r.status_code == 502 and "boum" in r.json()["detail"]
    _faux(monkeypatch, [subprocess.TimeoutExpired("x", 150)])
    assert client.post("/routeur/confirmer").status_code == 502
    _faux(monkeypatch, [(0, "pas du json")])
    assert client.post("/routeur/confirmer").status_code == 502


def test_avertissement_depuis_le_lan(client, monkeypatch):
    _faux(monkeypatch, [(0, ETAT_LAN), (0, {"etat": "en_attente"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"}, headers={"X-Real-IP": "192.168.42.50"})
    assert "avertissement" in r.json() and "3 minutes" in r.json()["avertissement"]
    _faux(monkeypatch, [(0, ETAT_LAN), (0, {"etat": "en_attente"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"}, headers={"X-Real-IP": "203.0.113.9"})
    assert "avertissement" not in r.json()
    # même réseau : pas d'avertissement
    _faux(monkeypatch, [(0, ETAT_LAN), (0, {"etat": "en_attente"})])
    mem = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100", "dhcp_fin": "192.168.42.199"}
    r = client.post("/routeur/appliquer", json={**mem, "confirmer": "routeur"}, headers={"X-Real-IP": "192.168.42.50"})
    assert "avertissement" not in r.json()


def test_retour_et_etat(client, monkeypatch):
    assert client.post("/routeur/retour", json={}).status_code == 400
    f = _faux(monkeypatch, [(0, {"etat": "inactif"})])
    assert client.post("/routeur/retour", json={"confirmer": "retour"}).status_code == 200
    assert f.appels[0][0][-2:] == ["routeur-retour", "alice"]
    f = _faux(monkeypatch, [(0, ETAT_LAN)])
    assert client.get("/routeur/etat").json()["etat"] == "actif"
    assert f.appels[0][0] == ["sudo", "-n", "/usr/sbin/netmodesctl", "routeur-etat"]


def test_apercu_sans_sudo(client, monkeypatch):
    f = _faux(monkeypatch, [])
    r = client.post("/routeur/apercu", json=CONFIG)
    assert r.status_code == 200 and r.json()["fichiers"]
    assert client.post("/routeur/apercu", json={**CONFIG, "adresse": "192.168.255.1/24"}).status_code == 400
    assert f.appels == []


def test_acteur_invalide_400(client, monkeypatch):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "a b;rm"}
    f = _faux(monkeypatch, [])
    assert client.post("/routeur/confirmer").status_code == 400 and f.appels == []


def test_anciens_chemins_409_sur_mochabin(client, monkeypatch):
    monkeypatch.setattr(main, "est_mochabin", lambda: True)
    for chemin, corps in (("/apply_mode", {"mode": "router"}), ("/auto_apply", {}), ("/rollback", None)):
        r = client.post(chemin, json=corps) if corps is not None else client.post(chemin)
        assert r.status_code == 409 and "WAN" in r.json()["detail"], chemin


def test_anciens_chemins_inchanges_ailleurs(client, monkeypatch):
    monkeypatch.setattr(main, "est_mochabin", lambda: False)
    assert client.post("/apply_mode", json={"mode": "inconnu"}).status_code == 400


def test_est_mochabin_lit_le_modele(tmp_path, monkeypatch):
    m = tmp_path / "model"
    monkeypatch.setattr(routeur_api, "MODELES", (m,))
    assert routeur_api.est_mochabin() is False
    m.write_bytes(b"Globalscale Technologies MOCHAbin\x00")
    assert routeur_api.est_mochabin() is True
    m.write_bytes(b"Raspberry Pi\x00")
    assert routeur_api.est_mochabin() is False


def test_routes_mutantes_gardees():
    for r in routeur_api.router.routes:
        if "POST" in r.methods:
            assert any(d.call is require_jwt for d in r.dependant.dependencies), r.path


def test_pas_de_subprocess_dans_async():
    arbre = ast.parse(Path(routeur_api.__file__).read_text())
    for fn in ast.walk(arbre):
        if isinstance(fn, ast.AsyncFunctionDef):
            assert "subprocess" not in ast.dump(fn)


def test_etat_sans_sub(client, monkeypatch):
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    _faux(monkeypatch, [(0, ETAT_LAN)])
    assert client.get("/routeur/etat").status_code == 200


def test_precontrole_en_echec_n_empeche_pas_d_appliquer(client, monkeypatch):
    _faux(monkeypatch, [(1, {"erreur": "x"}), (0, {"etat": "en_attente"})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    assert r.status_code == 200 and "avertissement" not in r.json()


def test_argv_conformes_au_sudoers(client, monkeypatch):
    f = _faux(monkeypatch, [(0, ETAT_LAN), (0, ETAT_LAN), (0, {}), (0, {}), (0, {})])
    client.get("/routeur/etat")
    client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    client.post("/routeur/confirmer")
    client.post("/routeur/retour", json={"confirmer": "retour"})
    ctl = "/usr/sbin/netmodesctl"
    assert len(f.appels) == 5
    for argv, _ in f.appels:
        assert argv == ["sudo", "-n", ctl, "routeur-etat"] or (
            len(argv) == 5 and argv[:3] == ["sudo", "-n", ctl]
            and argv[3] in ("routeur-appliquer", "routeur-confirmer", "routeur-retour") and argv[4] == "alice"), argv
