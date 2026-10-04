# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
import time

import pytest
from fastapi.testclient import TestClient
from secubox_core import auth

from api import main
from webfilter import analyse, listes, magasin

CONF = '''
[[categorie]]
id = "adulte"
libelle = "Contenu adulte"
mode = "observe"
  [[categorie.source]]
  nom = "s1"
  url = "https://x.example/a"
  format = "domaines"
  licence = "GPL-3.0"
  taille_max = 1000
'''
AUJOURD_HUI = time.strftime("%Y-%m-%d", time.gmtime())


@pytest.fixture
def banc(tmp_path, monkeypatch):
    conf = tmp_path / "w.toml"
    conf.write_text(CONF)
    (tmp_path / "listes" / "adulte").mkdir(parents=True)
    listes.Index.depuis(["evil.example.com"]).ecrire(tmp_path / "listes" / "adulte" / "s1.idx")
    (tmp_path / "listes" / "adulte" / "s1.json").write_text(json.dumps({"n": 1, "ts": 1791090000, "sha256": "x", "licence": "GPL-3.0", "url": "https://x.example/a"}))
    m = magasin.Magasin(tmp_path / "webfilter.db")
    now = int(time.time())
    m.ajouter([(analyse.Evenement(now, "192.168.1.95", "a.evil.example.com", "A", "NOERROR"), "adulte")] * 3
              + [(analyse.Evenement(now, "192.168.1.5", "b.evil.example.com", "A", "NOERROR"), "adulte")], exclus=set())
    monkeypatch.setattr(main, "CATALOGUE", conf)
    monkeypatch.setattr(main, "ETAT", tmp_path)
    main.app.dependency_overrides.clear()
    yield tmp_path
    main.app.dependency_overrides.clear()


def lecteur():
    main.app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "lecteur"}


def admin():
    lecteur()
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}


def test_etat_lisible_sans_nom_d_appareil_ni_chemin(banc):
    lecteur()
    r = TestClient(main.app).get("/etat")
    assert r.status_code == 200
    d = r.json()
    c = d["categories"][0]
    assert c["id"] == "adulte" and c["mode"] == "observe" and c["requetes_7j"] == 4
    assert c["sources"] == [{"nom": "s1", "licence": "GPL-3.0", "n": 1, "ts": 1791090000}]
    assert d["mode_global"] == "observe"
    assert "192.168" not in r.text and "/var/lib" not in r.text and str(banc) not in r.text


def test_detail_par_appareil_refuse_sans_jeton_administrateur(banc):
    lecteur()                                                      # lecture seule : pas d'administrateur
    c = TestClient(main.app)
    assert c.get("/stats").status_code in (401, 403)
    assert c.get("/categories/adulte/domaines").status_code in (401, 403)
    assert c.post("/sync").status_code in (401, 403)


def test_stats_et_domaines_pour_l_administrateur(banc):
    admin()
    c = TestClient(main.app)
    d = c.get("/stats?jours=7").json()
    assert d["par_categorie"] == {"adulte": 4} and d["par_client"] == {"192.168.1.95": {"adulte": 3}, "192.168.1.5": {"adulte": 1}}
    dom = c.get("/categories/adulte/domaines?jours=7&n=1").json()
    assert dom["domaines"] == [{"domaine": "a.evil.example.com", "n": 3}]


@pytest.mark.parametrize("chemin", ["/stats?jours=0", "/stats?jours=31", "/stats?jours=abc", "/categories/adulte/domaines?n=0",
                                    "/categories/adulte/domaines?n=501"])
def test_parametres_hors_bornes(banc, chemin):
    admin()
    assert TestClient(main.app).get(chemin).status_code == 422


def test_categorie_inconnue_ou_hostile(banc):
    admin()
    c = TestClient(main.app)
    assert c.get("/categories/inconnue/domaines").status_code == 404
    assert c.get("/categories/..%2F..%2Fetc/domaines").status_code == 404


def test_catalogue_illisible_donne_503(banc, monkeypatch):
    lecteur()
    (banc / "w.toml").write_text("[[categorie\n")
    r = TestClient(main.app).get("/etat")
    assert r.status_code == 503 and "catalogue" in r.json()["detail"]


def test_sync_depose_une_demande_sans_telecharger(banc, monkeypatch):
    admin()
    appels = []
    monkeypatch.setattr("webfilter.sources.synchroniser", lambda *a, **k: appels.append(1))
    r = TestClient(main.app).post("/sync")
    assert r.status_code == 202 and r.json() == {"statut": "demandee"}
    assert (banc / "sync.demande").is_file() and appels == []               # le téléchargement est l'affaire de l'unité systemd
    assert oct((banc / "sync.demande").stat().st_mode & 0o777) == "0o640"


def test_sync_deja_demandee_donne_409(banc):
    admin()
    c = TestClient(main.app)
    assert c.post("/sync").status_code == 202
    r = c.post("/sync")
    assert r.status_code == 409 and "déjà" in r.json()["detail"]


def test_demande_perimee_est_remplacee(banc):
    admin()
    import os
    (banc / "sync.demande").write_text("x")
    vieux = time.time() - 11 * 60
    os.utime(banc / "sync.demande", (vieux, vieux))
    assert TestClient(main.app).post("/sync").status_code == 202
    assert time.time() - (banc / "sync.demande").stat().st_mtime < 60


def test_demande_refusee_si_le_catalogue_est_illisible(banc):
    admin()
    (banc / "w.toml").write_text("[[categorie\n")
    assert TestClient(main.app).post("/sync").status_code == 503
    assert not (banc / "sync.demande").exists()


def test_health_sans_authentification():
    assert TestClient(main.app).get("/health").json()["status"] == "ok"

