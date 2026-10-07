# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""IPv6 Guardian — routes : lecture gardée, jamais d'écriture, vivacité publique."""
import inspect

from fastapi.testclient import TestClient

from api import main, service
from tests.test_verdict_service import Faux


def test_health_est_publique():
    r = TestClient(main.app).get("/health")
    assert r.status_code == 200 and r.json()["module"] == "ipv6guard"


def test_status_et_appareils_sont_gardes_en_lecture(monkeypatch):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")        # pas de lecture ouverte au LAN : déterministe quelle que soit la machine
    c = TestClient(main.app)
    assert c.get("/status").status_code in (401, 403)
    assert c.get("/appareils").status_code in (401, 403)


def test_status_avec_lecture_autorisee_rend_verdict_etapes_appareils(monkeypatch):
    from secubox_core import auth
    main.app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "t"}
    try:
        monkeypatch.setattr(main, "_surveillance", service.Surveillance(Faux(), ttl_mdns=300))
        r = TestClient(main.app).get("/status")
        assert r.status_code == 200
        j = r.json()
        assert j["verdict"]["niveau"] == "a_verifier" and [e["id"] for e in j["etapes"]] == ["appareils", "services", "bloquees", "exceptions"]
        assert j["appareils"] and all("mac" not in a for a in j["appareils"])
    finally:
        main.app.dependency_overrides.clear()


def test_aucune_route_n_ecrit():
    verbes = {m for r in main.app.routes for m in getattr(r, "methods", set())}
    assert verbes <= {"GET", "HEAD", "OPTIONS"}


def test_les_gestionnaires_bloquants_ne_sont_pas_des_coroutines():
    assert not inspect.iscoroutinefunction(main.status) and not inspect.iscoroutinefunction(main.appareils)
