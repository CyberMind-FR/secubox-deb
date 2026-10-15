# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2728 — routes d'administration de la détection : garde `admin.modules`, aucune route publique, erreurs en 400."""
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import decouverte as D, maitre as MA  # noqa: E402

MDP = "une-phrase-longue-et-sure"
PROFIL = {"box": {"fuseau": "Europe/Paris", "langue": "fr", "clavier": "fr"}, "admin": {"mot_de_passe": MDP, "confirmation": MDP},
          "reseau": {"mode": "routeur", "domaine": "gk3.secubox.in"}, "services": {"profil": "full"}, "maillage": {"mode": "plus_tard"}, "apt": {"auto": True, "heure": "03:00"}}
ROUTES = [("GET", "/maitre/decouverte", None), ("POST", "/maitre/decouverte/analyser", None), ("POST", "/maitre/decouverte/preparer", {"adresse": "192.168.1.9", "nom": "gk3"}),
          ("PUT", "/maitre/decouverte/reglages", {"auto": False}), ("DELETE", "/maitre/decouverte/192.168.1.9", None)]


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "pp"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    (tmp_path / "jeton").write_text("code\n")
    (tmp_path / "jeton-local").write_text("local\n")
    from api import main
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    from fastapi.testclient import TestClient
    return TestClient(main.app), main


def admin(main):
    main.app.dependency_overrides[main._admin[0].dependency] = lambda: {"sub": "admin"}


@pytest.mark.parametrize("methode,chemin,corps", ROUTES)
def test_toutes_les_routes_exigent_un_administrateur(api, methode, chemin, corps):
    c, _ = api
    r = c.request(methode, chemin, json=corps)
    assert r.status_code in (401, 403), (chemin, r.status_code)


@pytest.mark.parametrize("methode,chemin,corps", ROUTES)
def test_les_jetons_de_l_assistant_n_ouvrent_pas_ces_routes(api, methode, chemin, corps):
    """Le jeton local, le code d'appairage et un secret de session distante sont ceux d'UNE box neuve : ils ne donnent aucun droit sur le maître."""
    c, _ = api
    for jeton in ("code", "local"):
        assert c.request(methode, chemin, json=corps, headers={"X-Premier-Pas": jeton}).status_code in (401, 403)


def test_etat_vide_puis_analyse(api, monkeypatch):
    c, main = api
    admin(main)
    assert c.get("/maitre/decouverte").json() == {"boxes": [], "reglages": {"auto": False, "profil": "", "mode": "remplir"}}
    monkeypatch.setattr(D, "voisins", lambda *a, **k: ["192.168.1.9"])
    monkeypatch.setattr(D, "sonde", lambda adresse, client=None: {"fait": False, "complet": False, "nom": "gk3"})
    r = c.post("/maitre/decouverte/analyser").json()
    assert r["trouvees"] == 1 and r["boxes"][0]["etat"] == "nouvelle" and r["boxes"][0]["nom"] == "gk3"
    assert c.get("/maitre/decouverte").json()["boxes"][0]["adresse"] == "192.168.1.9"


def test_preparer_une_box_detectee(api, monkeypatch):
    c, main = api
    admin(main)
    MA.enregistre("gk3", PROFIL)
    monkeypatch.setattr(D, "voisins", lambda *a, **k: ["192.168.1.9"])
    monkeypatch.setattr(D, "sonde", lambda adresse, client=None: {"fait": False, "complet": False, "nom": None})
    c.post("/maitre/decouverte/analyser")
    monkeypatch.setattr(MA, "pousse", lambda nom, adresse, code, mode, client=None, par="": {"ok": True, "faites": ["Nom"], "complet": True, "reprendre": "appliquer"})
    r = c.post("/maitre/decouverte/preparer", json={"adresse": "192.168.1.9", "nom": "gk3", "mode": "remplir"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert c.get("/maitre/decouverte").json()["boxes"][0]["etat"] == "preparee"


def test_preparer_une_box_non_detectee_est_une_erreur_claire(api):
    c, main = api
    admin(main)
    r = c.post("/maitre/decouverte/preparer", json={"adresse": "192.168.1.9", "nom": "gk3"})
    assert r.status_code == 400 and "détectée" in r.json()["detail"]


def test_preparer_une_adresse_publique_est_refuse(api):
    c, main = api
    admin(main)
    assert c.post("/maitre/decouverte/preparer", json={"adresse": "8.8.8.8", "nom": "gk3"}).status_code == 400


def test_reglages_valides_et_refuses(api):
    c, main = api
    admin(main)
    MA.enregistre("gk3", PROFIL)
    assert c.put("/maitre/decouverte/reglages", json={"auto": True, "profil": "gk3", "mode": "proposer"}).json()["auto"] is True
    r = c.put("/maitre/decouverte/reglages", json={"auto": True, "profil": "gk3", "mode": "forcer"})
    assert r.status_code == 400 and "forcer" in r.json()["detail"]


def test_oublier_une_box(api, monkeypatch):
    c, main = api
    admin(main)
    monkeypatch.setattr(D, "voisins", lambda *a, **k: ["192.168.1.9"])
    monkeypatch.setattr(D, "sonde", lambda adresse, client=None: {"fait": False, "complet": False, "nom": None})
    c.post("/maitre/decouverte/analyser")
    assert c.delete("/maitre/decouverte/192.168.1.9").json() == {"ok": True}
    assert c.get("/maitre/decouverte").json()["boxes"] == []


def test_pousser_sans_code_est_accepte_par_la_route_existante(api, monkeypatch):
    c, main = api
    admin(main)
    vu = {}
    monkeypatch.setattr(MA, "pousse", lambda nom, adresse, code, mode, client=None, par="": vu.update(code=code) or {"ok": True})
    assert c.post("/maitre/pousser", json={"nom": "gk3", "adresse": "192.168.1.9", "mode": "remplir"}).status_code == 200 and vu["code"] == ""
