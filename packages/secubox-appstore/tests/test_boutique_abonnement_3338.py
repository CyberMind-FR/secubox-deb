# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 volet 3 — la boutique suit la formule de la box : une app hors formule est annoncée « Disponible avec la
formule X » et le SERVEUR refuse son installation ; une box sans abonnement (maître, atelier) installe tout."""
import importlib
import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG.parents[1] / "common"))
from fastapi.testclient import TestClient  # noqa: E402

PROFILS = [{"name": "lite", "label": "Léger", "modules": ["secubox-dns"]},
           {"name": "media-lab", "label": "Médias", "modules": ["secubox-dns", "secubox-jellyfin"]}]


@pytest.fixture()
def api(monkeypatch, tmp_path):
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "load_catalog", lambda: [{"name": "secubox-dns", "tier": "lite"},
                                                    {"name": "secubox-jellyfin", "tier": "lite"}])
    monkeypatch.setattr(m, "compute_state", lambda force=False: {
        "secubox-dns": {"name": "secubox-dns", "category": "network", "tier": "lite", "installed": False,
                        "state": "available", "running": False},
        "secubox-jellyfin": {"name": "secubox-jellyfin", "category": "media", "tier": "lite", "installed": False,
                             "state": "available", "running": False}})
    monkeypatch.setattr(m, "_profils", lambda: PROFILS)
    lances = []
    monkeypatch.setattr(m, "_appstorectl", lambda argv: lances.append(argv) or (0, "ok", ""))
    m.ABONNEMENT_FILE = tmp_path / "abonnement.json"
    m.lances = lances
    yield m
    m.app.dependency_overrides.clear()


def _abonne(m, **kw):
    d = {"formule": "Léger", "profil": "lite", "statut": "actif",
         "formules": [{"nom": "Léger", "profil": "lite"}, {"nom": "Médias", "profil": "media-lab"}]}
    d.update(kw)
    m.ABONNEMENT_FILE.write_text(json.dumps(d), encoding="utf-8")


def test_sans_abonnement_tout_est_permis(api):
    c = TestClient(api.app)
    mods = {x["name"]: x for x in c.get("/catalog").json()["modules"]}
    assert not mods["secubox-jellyfin"].get("hors_formule")
    assert c.post("/module/secubox-jellyfin/action/install").status_code == 202


def test_hors_formule_annonce_et_refuse_par_le_serveur(api):
    _abonne(api)
    c = TestClient(api.app)
    mods = {x["name"]: x for x in c.get("/catalog").json()["modules"]}
    assert mods["secubox-jellyfin"]["hors_formule"] is True
    assert mods["secubox-jellyfin"]["formule_requise"] == "Médias"
    assert not mods["secubox-dns"].get("hors_formule")
    r = c.post("/module/secubox-jellyfin/action/install")
    assert r.status_code == 403 and "Médias" in r.json()["detail"]
    assert c.post("/module/secubox-dns/action/install").status_code == 202


@pytest.mark.parametrize("statut", ["suspendu", "echu", "revoque"])
def test_abonnement_inactif_refuse_toute_installation(api, statut):
    _abonne(api, statut=statut)
    r = TestClient(api.app).post("/module/secubox-dns/action/install")
    assert r.status_code == 403 and "abonnement" in r.json()["detail"]


def test_fichier_illisible_refuse(api):
    api.ABONNEMENT_FILE.write_text("{pas du json", encoding="utf-8")
    r = TestClient(api.app).post("/module/secubox-dns/action/install")
    assert r.status_code == 403
