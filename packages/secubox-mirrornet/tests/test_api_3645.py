# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3645 — API de secubox-mirrornet : lecture seule, gardes, ledger privé, base absente."""
import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("SBX_MIRRORNET_DB", str(tmp_path / "m.db"))
    from secubox_mirrornet import config
    importlib.reload(config)
    main = importlib.import_module("api.main")
    monkeypatch.setattr(main.config, "BASE", tmp_path / "m.db")
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield main, tmp_path / "m.db"
    main.app.dependency_overrides.clear()


def test_sante_publique_et_base_absente(api):
    main, base = api
    c = TestClient(main.app)
    assert c.get("/api/v1/mirrornet/health").json()["phase"] == 4
    assert c.get("/api/v1/mirrornet/services").status_code == 503


def test_lectures_sur_base_vide(api):
    main, base = api
    from secubox_mirrornet import ledger, schema
    schema.initialiser(base)
    c = TestClient(main.app)
    assert c.get("/api/v1/mirrornet/schema").json() == {"version": 5, "attendue": 5}
    st = c.get("/api/v1/mirrornet/status").json()
    assert st["base"] is True and st["schema"] == 5 and st["ecriture"] is True and st["n_offer"] == 0
    for chemin, cle in (("services", "services"), ("datasets", "datasets"), ("subscriptions", "subscriptions"),
                        ("economy/distribution-rules", "rules")):
        r = c.get(f"/api/v1/mirrornet/{chemin}")
        assert r.status_code == 200 and r.json()[cle] == [] and r.json()["count"] == 0, chemin
    cx = schema.ouvrir(base)
    a, b = ledger.compte(cx, "credits", "did:plc:" + "a" * 32), ledger.compte(cx, "credits", "did:plc:" + "b" * 32)
    ledger.ecrire_transaction(cx, "essai", [(a, -3), (b, 3)])
    cx.close()
    j = c.get("/api/v1/mirrornet/economy/ledger").json()
    assert j["integre"] is True and len(j["ecritures"]) == 2 and j["tete"]["rang"] == 2
    compte = c.get("/api/v1/mirrornet/economy/account").json()
    assert compte["valeur_monetaire"] is False and len(compte["comptes"]) == 2


def test_gardes_et_ecritures_administrateur():
    main = importlib.import_module("api.main")
    for route in main.app.routes:
        chemin = getattr(route, "path", "")
        if not chemin.startswith("/api/v1/mirrornet"):
            continue
        deps = [d.call for d in route.dependant.dependencies]
        if not route.methods <= {"GET", "HEAD"}:                     # phase 3 (#3647) : toute écriture = administrateur
            assert main.require_jwt in deps, chemin
            continue
        if chemin.endswith("/health"):
            continue
        if any(x in chemin for x in ("/economy/account", "/economy/ledger", "/subscriptions")):
            assert main.require_jwt in deps, chemin                   # ledger et relations privés : administrateur
        else:
            assert main.require_lecture in deps or main.require_jwt in deps, chemin
