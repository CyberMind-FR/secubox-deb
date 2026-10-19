# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2819 — GET /api/v1/profiles/comparatif : contenu des profils (genere des meta-paquets) + profil ACTIF et modules installes sur CETTE box (dpkg)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
from fastapi.testclient import TestClient  # noqa: E402

import api.web as web  # noqa: E402

CONTENU = {"version": 1, "espaces": [], "absents_de_minimal": [],
           "profils": [{"id": "minimal", "modules": [{"paquet": "secubox-dpi", "espace": "protection"}]},
                       {"id": "lite", "modules": [{"paquet": "secubox-dpi", "espace": "protection"}, {"paquet": "secubox-waf-ng", "espace": "protection"}]},
                       {"id": "isp", "modules": [{"paquet": "secubox-dpi", "espace": "protection"}, {"paquet": "secubox-mail", "espace": "services"}]},
                       {"id": "full", "modules": [{"paquet": "secubox-dpi", "espace": "protection"}, {"paquet": "secubox-webos", "espace": "autres"}]}]}


def statut(*paquets, absents=()):
    out = []
    for p in paquets:
        out.append(f"Package: {p}\nStatus: install ok installed\nVersion: 1.0\n")
    for p in absents:
        out.append(f"Package: {p}\nStatus: deinstall ok config-files\nVersion: 1.0\n")
    return "\n".join(out)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    (tmp_path / "contenu.json").write_text(json.dumps(CONTENU))
    monkeypatch.setenv("SECUBOX_PROFILS_CONTENU", str(tmp_path / "contenu.json"))
    monkeypatch.setenv("SECUBOX_DPKG_STATUS", str(tmp_path / "status"))
    app = web.create_app()
    app.dependency_overrides[web.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app), tmp_path


def test_le_profil_actif_est_celui_dont_le_meta_paquet_est_installe(client):
    c, d = client
    (d / "status").write_text(statut("secubox-lite", "secubox-dpi", "secubox-waf-ng"))
    j = c.get("/api/v1/profiles/comparatif").json()
    assert j["actif"] == "lite" and j["profils_installes"] == ["lite"]


def test_isp_installe_tire_lite_mais_le_plus_large_est_actif(client):
    c, d = client
    (d / "status").write_text(statut("secubox-lite", "secubox-isp"))
    j = c.get("/api/v1/profiles/comparatif").json()
    assert j["actif"] == "isp" and j["profils_installes"] == ["lite", "isp"]


def test_un_meta_paquet_desinstalle_n_est_pas_actif(client):
    c, d = client
    (d / "status").write_text(statut("secubox-minimal", absents=("secubox-lite",)))
    assert c.get("/api/v1/profiles/comparatif").json()["actif"] == "minimal"


def test_aucun_meta_paquet_installe_ne_devine_rien(client):
    c, d = client
    (d / "status").write_text(statut("secubox-dpi"))
    j = c.get("/api/v1/profiles/comparatif").json()
    assert j["actif"] is None and j["profils_installes"] == []


def test_les_modules_installes_sont_ceux_des_profils_presents_dans_dpkg(client):
    c, d = client
    (d / "status").write_text(statut("secubox-lite", "secubox-dpi", "secubox-mail", "secubox-inconnu-des-profils"))
    j = c.get("/api/v1/profiles/comparatif").json()
    assert sorted(j["installes"]) == ["secubox-dpi", "secubox-mail"]       # les modules des profils ; ni les meta-paquets, ni le reste de dpkg
    assert "secubox-inconnu-des-profils" not in j["installes"]


def test_le_contenu_est_rendu_tel_quel(client):
    c, d = client
    (d / "status").write_text(statut("secubox-lite"))
    assert c.get("/api/v1/profiles/comparatif").json()["profils"] == CONTENU["profils"]


def test_contenu_absent_est_une_503_explicite_pas_une_liste_vide(client):
    c, d = client
    (d / "contenu.json").unlink()
    r = c.get("/api/v1/profiles/comparatif")
    assert r.status_code == 503 and "contenu" in r.json()["detail"].lower()


def test_dpkg_illisible_laisse_le_contenu_et_le_dit(client):
    c, d = client
    j = c.get("/api/v1/profiles/comparatif").json()      # pas de fichier status
    assert j["actif"] is None and j["dpkg"] == "illisible" and j["profils"] == CONTENU["profils"]


def test_la_route_est_gardee_par_require_lecture():
    src = (Path(__file__).resolve().parents[1] / "api" / "web.py").read_text()
    ligne = next(l for l in src.splitlines() if '"/api/v1/profiles/comparatif"' in l and "@app.get" in l)
    assert "require_lecture" in ligne
