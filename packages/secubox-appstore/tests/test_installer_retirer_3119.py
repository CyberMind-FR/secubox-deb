# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3119 — installer et retirer un module depuis l'App Store (gk1, gk2).

La page avait un bouton « Installer » grisé (« non reprise » à la refonte Aurora) et aucun bouton de retrait, alors que
l'API sait installer, retirer (confirmation = retaper le nom) et réparer. Mais HAProxy coupe à 30 s (`timeout server`) :
une installation apt synchrone finirait en 504. Installer, retirer et réparer deviennent donc des TÂCHES DE FOND :
la requête rend 202, la page interroge GET /jobs."""
import importlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG.parents[1] / "common"))
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def api(monkeypatch):
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "load_catalog", lambda: [{"name": "secubox-relais", "tier": "lite"}, {"name": "secubox-dns", "tier": "lite"}])
    monkeypatch.setattr(m, "compute_state", lambda force=False: {
        "secubox-relais": {"installed": True, "state": "installed", "running": False},
        "secubox-dns": {"installed": False, "state": "available", "running": False}})
    yield m
    m.app.dependency_overrides.clear()


def _attend(c, nom, etat_final=None, delai=5):
    fin = time.time() + delai
    while time.time() < fin:
        j = c.get("/jobs").json()["jobs"].get(nom)
        if j and j["etat"] != "en-cours":
            return j
        time.sleep(0.02)
    raise AssertionError("tâche jamais terminée")


def test_delai_par_verbe(monkeypatch):
    import api.main as m
    vus = []

    def faux(cmd, **kw):
        vus.append((cmd[-2], kw.get("timeout")))
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    monkeypatch.setattr(m.subprocess, "run", faux)
    for verbe in ("install", "repair", "remove", "stop"):
        m._appstorectl([verbe, "secubox-relais"])
    assert dict(vus) == {"install": 600, "repair": 600, "remove": 300, "stop": 90}


def test_retrait_rend_202_puis_la_tache_se_termine(api, monkeypatch):
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (0, "removed secubox-relais", ""))
    with TestClient(api.app) as c:
        r = c.post("/module/secubox-relais/action/remove?confirmer=secubox-relais")
        assert r.status_code == 202, r.text
        assert r.json()["status"] == "en-cours" and r.json()["module"] == "secubox-relais"
        j = _attend(c, "secubox-relais")
    assert j["etat"] == "ok" and j["verbe"] == "remove" and "removed" in j["message"]


def test_installation_valide_sur_le_catalogue_et_rend_202(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (appels.append(a) or 0, "installed secubox-dns", ""))
    with TestClient(api.app) as c:
        assert c.post("/module/dns/action/install").status_code == 202
        _attend(c, "secubox-dns")
        assert c.post("/module/inconnu/action/install").status_code == 404
    assert appels == [["install", "secubox-dns"]]


def test_refus_du_controleur_rapporte_dans_la_tache(api, monkeypatch):
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (7, "", "appstorectl: secubox-relais est requis par : secubox-x"))
    with TestClient(api.app) as c:
        assert c.post("/module/secubox-relais/action/remove?confirmer=secubox-relais").status_code == 202
        j = _attend(c, "secubox-relais")
    assert j["etat"] == "refuse" and j["code"] == 409 and "requis par" in j["message"]


def test_une_panne_est_distincte_d_un_refus(api, monkeypatch):
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (1, "", "disque plein"))
    with TestClient(api.app) as c:
        c.post("/module/secubox-relais/action/remove?confirmer=secubox-relais")
        j = _attend(c, "secubox-relais")
    assert j["etat"] == "echec" and j["code"] == 500


def test_une_seule_operation_a_la_fois(api, monkeypatch):
    import threading
    libere = threading.Event()
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (libere.wait(5) and 0, "ok", ""))
    with TestClient(api.app) as c:
        assert c.post("/module/dns/action/install").status_code == 202
        r = c.post("/module/secubox-relais/action/remove?confirmer=secubox-relais")
        assert r.status_code == 409 and "secubox-dns" in r.json()["detail"]
        libere.set()
        _attend(c, "secubox-dns")


def test_retrait_exige_de_retaper_le_nom(api, monkeypatch):
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (0, "removed", ""))
    with TestClient(api.app) as c:
        assert c.post("/module/secubox-relais/action/remove").status_code == 428
        assert c.post("/module/secubox-relais/action/remove?confirmer=relais").status_code == 428
        assert c.get("/jobs").json()["jobs"] == {}                 # rien n'a démarré


def test_les_verbes_courts_restent_synchrones(api, monkeypatch):
    monkeypatch.setattr(api, "_appstorectl", lambda a, input_text=None: (0, "stopped", ""))
    with TestClient(api.app) as c:
        r = c.post("/module/secubox-relais/action/stop")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_jobs_exige_une_session(api, monkeypatch):
    import secubox_core.auth as auth
    monkeypatch.setattr(auth, "mode_tableau_de_bord_actif", lambda: False)   # ce poste peut avoir le mode LAN sans jeton
    api.app.dependency_overrides.pop(api.require_lecture, None)
    assert TestClient(api.app).get("/jobs").status_code in (401, 403)
