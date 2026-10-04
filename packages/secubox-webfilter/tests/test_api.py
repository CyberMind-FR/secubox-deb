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


def test_status_alias_de_etat_et_dernier_evenement(banc):
    lecteur()
    c = TestClient(main.app)
    assert c.get("/status").json() == c.get("/etat").json()
    assert isinstance(c.get("/etat").json()["dernier_evenement"], str)           # horodatage ISO : le comptage est-il vivant ?


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



# ── phase 2 : profils, appareils, application (#1962) ─────────────────────────────────────────────────────────────────────────────
CONF2 = CONF + '''
[[categorie]]
id = "jeux"
libelle = "Jeux d'argent"
mode = "observe"
  [[categorie.source]]
  nom = "s2"
  url = "https://x.example/b"
  format = "domaines"
  licence = "GPL-3.0"
  taille_max = 1000
'''
MAC1, MAC2 = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


@pytest.fixture
def banc2(tmp_path, monkeypatch):
    conf = tmp_path / "w.toml"
    conf.write_text(CONF2)
    monkeypatch.setattr(main, "CATALOGUE", conf)
    monkeypatch.setattr(main, "ETAT", tmp_path)
    for cat, n in (("adulte", 84000), ("jeux", 227000)):
        (tmp_path / "listes" / cat).mkdir(parents=True)
        (tmp_path / "listes" / cat / ("s1.json" if cat == "adulte" else "s2.json")).write_text(json.dumps({"n": n, "ts": 1791090000, "licence": "GPL-3.0"}))
    main.app.dependency_overrides.clear()
    yield tmp_path
    main.app.dependency_overrides.clear()


def cfg_fichier(banc):
    return json.loads((banc / "config.json").read_text())


def test_routes_de_profils_et_appareils_reservees_a_l_administrateur(banc2):
    lecteur()
    c = TestClient(main.app)
    for methode, chemin in (("get", "/profils"), ("post", "/profils"), ("delete", "/profils/enfants"), ("get", "/appareils"), ("post", f"/appareils/{MAC1}"),
                            ("delete", f"/appareils/{MAC1}"), ("get", "/appliquer"), ("post", "/appliquer")):
        assert getattr(c, methode)(chemin).status_code in (401, 403), (methode, chemin)


def test_profils_initiaux_et_modeles(banc2):
    admin()
    d = TestClient(main.app).get("/profils").json()
    assert d["version"] == 0 and list(d["profils"]) == ["defaut"] and d["profils"]["defaut"]["categories"] == {"adulte": "observe", "jeux": "observe"}
    assert d["modeles"]["enfants"]["categories"] == {"adulte": "block", "jeux": "block"} and "adultes" in d["modeles"]
    assert not (banc2 / "config.json").exists()                                   # lire n'écrit rien


def test_creer_remplacer_et_versionner_un_profil(banc2):
    admin()
    c = TestClient(main.app)
    r = c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block", "jeux": "block"}, "autorise": ["education.example.org"]})
    assert r.status_code == 200 and r.json()["version"] == 1
    r = c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block", "jeux": "observe"}, "autorise": []})
    assert r.json()["version"] == 2 and r.json()["profils"]["enfants"]["categories"]["jeux"] == "observe"
    assert cfg_fichier(banc2)["version"] == 2 and oct((banc2 / "config.json").stat().st_mode & 0o777) == "0o600"
    assert sorted(p.name for p in banc2.iterdir() if p.name.startswith(".")) == []             # aucun résidu temporaire


@pytest.mark.parametrize("corps", [
    {"nom": "../x", "categories": {}, "autorise": []}, {"nom": "A B", "categories": {}, "autorise": []},
    {"nom": "ok", "categories": {"inconnue": "block"}, "autorise": []}, {"nom": "ok", "categories": {"adulte": "bloque"}, "autorise": []},
    {"nom": "ok", "categories": {}, "autorise": ['a.com"; local-zone: "."']}, {"nom": "ok", "categories": {}, "autorise": [f"d{i}.example.com" for i in range(201)]},
    {"nom": "x" * 40, "categories": {}, "autorise": []}, {"categories": {}}, {"nom": "ok", "categories": {}, "autorise": [], "extra": 1},
])
def test_profil_invalide_refuse_sans_rien_ecrire(banc2, corps):
    admin()
    assert TestClient(main.app).post("/profils", json=corps).status_code == 422
    assert not (banc2 / "config.json").exists()


def test_supprimer_un_profil(banc2):
    admin()
    c = TestClient(main.app)
    c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block"}, "autorise": []})
    c.post("/profils", json={"nom": "libre", "categories": {}, "autorise": []})
    c.post(f"/appareils/{MAC1}", json={"nom": "T", "profil": "enfants", "exceptions": {}})
    assert c.delete("/profils/defaut").status_code == 409
    assert c.delete("/profils/enfants").status_code == 409                          # utilisé par un appareil
    assert c.delete("/profils/inconnu").status_code == 404
    assert c.delete("/profils/libre").status_code == 200 and "libre" not in cfg_fichier(banc2)["profils"]


def test_assigner_un_appareil_et_le_lister(banc2):
    admin()
    c = TestClient(main.app)
    c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block"}, "autorise": []})
    (banc2 / "connus.json").write_text(json.dumps({MAC1: {"adresses": ["192.168.1.50"], "vu": 1791090000}, MAC2: {"adresses": ["192.168.1.51"], "vu": 1791090100}}))
    (banc2 / "resultat.json").write_text(json.dumps({"statut": "applique", "version": 1, "exclus": {MAC2: "geree par ad-guard"}}))
    r = c.post(f"/appareils/{MAC1.upper()}", json={"nom": "Tablette", "profil": "enfants", "exceptions": {"jeux": "observe"}})
    assert r.status_code == 200 and cfg_fichier(banc2)["appareils"][MAC1] == {"nom": "Tablette", "profil": "enfants", "exceptions": {"jeux": "observe"}}
    d = c.get("/appareils").json()
    assert d["assignes"][0]["mac"] == MAC1 and d["assignes"][0]["adresses"] == ["192.168.1.50"] and d["assignes"][0]["exclu"] is None
    assert [x["mac"] for x in d["connus"]] == [MAC2] and d["connus"][0]["exclu"] == "geree par ad-guard"       # connu, non assigné, signalé


@pytest.mark.parametrize("mac,corps", [("pas-une-mac", {"nom": "x", "profil": "defaut", "exceptions": {}}),
                                       (MAC1, {"nom": "x", "profil": "inexistant", "exceptions": {}}),
                                       (MAC1, {"nom": "x\ny", "profil": "defaut", "exceptions": {}}),
                                       (MAC1, {"nom": "x", "profil": "defaut", "exceptions": {"inconnue": "block"}}),
                                       (MAC1, {"nom": "x", "profil": "defaut", "exceptions": {"adulte": "autre"}})])
def test_appareil_invalide_refuse(banc2, mac, corps):
    admin()
    assert TestClient(main.app).post(f"/appareils/{mac}", json=corps).status_code == 422
    assert not (banc2 / "config.json").exists()


def test_retirer_un_appareil(banc2):
    admin()
    c = TestClient(main.app)
    c.post(f"/appareils/{MAC1}", json={"nom": "T", "profil": "defaut", "exceptions": {}})
    assert c.delete(f"/appareils/{MAC1}").status_code == 200 and cfg_fichier(banc2)["appareils"] == {}
    assert c.delete(f"/appareils/{MAC1}").status_code == 404


def test_appliquer_en_attente_et_estimation(banc2):
    admin()
    c = TestClient(main.app)
    assert c.get("/appliquer").json()["en_attente"] is False
    c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block", "jeux": "block"}, "autorise": ["education.example.org"]})
    for mac in (MAC1, MAC2):
        c.post(f"/appareils/{mac}", json={"nom": "T", "profil": "enfants", "exceptions": {}})
    d = c.get("/appliquer").json()
    assert d["en_attente"] is True and d["version"] == 3 and d["appliquee"] == 0 and d["dernier"] is None
    e = d["estimation"]
    assert e["zones"] == 84000 + 227000 + 1 and e["memoire_mo"] == round((84000 + 227000 + 1) * 0.35 / 1024) and 9 <= e["rechargement_s"] <= 10     # UNE vue pour les deux appareils
    (banc2 / "resultat.json").write_text(json.dumps({"statut": "applique", "version": 3, "zones": 311001, "vues": 2}))
    d2 = c.get("/appliquer").json()
    assert d2["en_attente"] is False and d2["appliquee"] == 3 and d2["dernier"]["statut"] == "applique"
    (banc2 / "resultat.json").write_text(json.dumps({"statut": "refuse", "version": 3, "message": "x"}))
    assert c.get("/appliquer").json()["en_attente"] is True                          # un refus n'a rien appliqué


def test_estimation_deux_configurations_deux_vues(banc2):
    admin()
    c = TestClient(main.app)
    c.post("/profils", json={"nom": "enfants", "categories": {"adulte": "block", "jeux": "block"}, "autorise": []})
    c.post(f"/appareils/{MAC1}", json={"nom": "A", "profil": "enfants", "exceptions": {}})
    c.post(f"/appareils/{MAC2}", json={"nom": "B", "profil": "enfants", "exceptions": {"jeux": "observe"}})
    assert c.get("/appliquer").json()["estimation"]["zones"] == (84000 + 227000) + 84000


def test_demande_d_application(banc2):
    admin()
    c = TestClient(main.app)
    r = c.post("/appliquer")
    assert r.status_code == 202 and r.json() == {"statut": "demandee"} and (banc2 / "appliquer.demande").is_file()
    assert c.post("/appliquer").status_code == 409
    import os
    vieux = time.time() - 11 * 60
    os.utime(banc2 / "appliquer.demande", (vieux, vieux))
    assert c.post("/appliquer").status_code == 202


def test_stats_et_etat_distinguent_bloque_et_observe(banc):
    admin()
    m = magasin.Magasin(banc / "webfilter.db")
    now = int(time.time())
    m.ajouter([(analyse.Evenement(now, "192.168.1.95", "a.evil.example.com", "A", "NOERROR"), "adulte", "bloque")] * 2
              + [(analyse.Evenement(now, "192.168.1.5", "b.evil.example.com", "A", "NOERROR"), "adulte", "observe")], exclus=set())
    c = TestClient(main.app)
    s = c.get("/stats?jours=7").json()
    # le fixture de la phase 1 a déjà compté 4 événements « observe » (3 pour .95, 1 pour .5) : on ajoute 2 « bloque » (.95) et 1 « observe » (.5)
    assert s["par_categorie_decision"]["adulte"] == {"bloque": 2, "observe": 5}
    assert s["par_client_decision"]["192.168.1.95"]["adulte"] == {"bloque": 2, "observe": 3}
    assert s["par_categorie"]["adulte"] == 7
    e = c.get("/etat").json()["categories"][0]
    assert e["bloque_7j"] == 2 and e["requetes_7j"] == 7 and "192.168" not in json.dumps(c.get("/etat").json())


def test_etat_inchange_pour_la_lecture_simple(banc2):
    lecteur()
    assert TestClient(main.app).get("/etat").status_code == 200
