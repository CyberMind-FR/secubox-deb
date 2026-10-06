# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""API de la cardlet Éphéméride : données du jour, hors-ligne, localisation absente, observations, gardes."""
from datetime import datetime
from unittest import mock
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

with mock.patch("pathlib.Path.mkdir"):
    from api import config, fournisseurs as F, main, observations

PARIS = ZoneInfo("Europe/Paris")
OM_METEO = {"current": {"temperature_2m": 14.2, "relative_humidity_2m": 71, "weather_code": 2, "wind_speed_10m": 11.0}}
OM_AIR = {"current": {"european_aqi": 28, "pm2_5": 6.1, "pm10": 9.0}}
MAINTENANT = datetime(2026, 10, 6, 12, 31, 45, tzinfo=PARIS)


@pytest.fixture
def api(tmp_path, monkeypatch):
    cfg = config.Config(timezone="Europe/Paris", nom_lieu="Aix-les-Bains", latitude=45.69, longitude=5.91)
    monkeypatch.setattr(main, "_config", lambda: cfg)
    monkeypatch.setattr(main, "_maintenant", lambda: MAINTENANT)
    monkeypatch.setattr(main, "_observations", lambda c=observations.Observations(tmp_path / "o.db"): c)
    monkeypatch.setattr(main, "_cache", lambda c=F.Cache(tmp_path / "cache.json"): c)
    monkeypatch.setattr(main, "_fournisseur_meteo", lambda: F.OpenMeteoMeteo(lecteur=lambda u, d: OM_METEO))
    monkeypatch.setattr(main, "_fournisseur_air", lambda: F.OpenMeteoAir(lecteur=lambda u, d: OM_AIR))
    monkeypatch.setattr(main, "_arriere_plan", lambda f: f())            # rafraîchissement synchrone en test
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(main.app), cfg
    main.app.dependency_overrides.clear()


def test_donnees_du_jour(api):
    c, _ = api
    j = c.get("/").json()
    assert j["fuseau"] == {"nom": "Europe/Paris", "decalage": "UTC+2", "decalage_minutes": 120}
    assert j["lieu"] == {"nom": "Aix-les-Bains", "latitude": 45.69, "longitude": 5.91, "approximatif": False}
    assert j["calendrier"]["semaine_iso"] == 41 and j["calendrier"]["jour_annee"] == 279 and j["calendrier"]["saison"] == "automne"
    assert j["calendrier"]["jour_semaine"] == "mardi" and j["calendrier"]["mois"] == "octobre"
    assert [s["nom"] for s in j["saints"]] == ["Bruno"]
    assert j["soleil"]["etat"] == "jour" and 0.3 < j["soleil"]["progression"] < 0.7
    assert j["soleil"]["lever"] < j["soleil"]["coucher"]
    assert j["lune"]["nom"] == "Dernier croissant" and j["lune"]["prochaine_phase"]["nom"] == "Nouvelle lune"
    assert j["maintenant"].startswith("2026-10-06T12:31:45+02:00") and isinstance(j["serveur_epoch_ms"], int)


def test_meteo_et_air_disponibles(api):
    j = api[0].get("/").json()
    assert j["meteo"]["temperature_c"] == 14.2 and j["meteo"]["condition"] == "Peu nuageux" and j["meteo_etat"]["etat"] == "frais"
    assert j["air"]["indice"] == 28 and j["air"]["niveau"] == "Correct"


def test_sans_internet_la_carte_reste_complete(api, monkeypatch):
    c, _ = api
    def ko(u, d):
        raise OSError("Network is unreachable")
    monkeypatch.setattr(main, "_fournisseur_meteo", lambda: F.OpenMeteoMeteo(lecteur=ko))
    monkeypatch.setattr(main, "_fournisseur_air", lambda: F.OpenMeteoAir(lecteur=ko))
    r = c.get("/")
    j = r.json()
    assert r.status_code == 200 and j["meteo"] is None and j["meteo_etat"]["etat"] == "indisponible"
    assert j["air"] is None
    assert j["soleil"]["lever"] and j["lune"]["nom"] and j["saints"] and j["calendrier"]["saison"] == "automne"
    assert "Network" not in r.text and "unreachable" not in r.text                       # jamais d'erreur technique brute


def test_meteo_perimee_est_servie_marquee_perimee(api, monkeypatch, tmp_path):
    c, cfg = api
    cache = main._cache()
    cache.obtenir("meteo", cfg.meteo.ttl_s, lambda: F.vers_dict(F.Meteo(12.0, "Couvert", "nuage", 3)), maintenant=1.0)
    def ko(u, d):
        raise OSError("down")
    monkeypatch.setattr(main, "_fournisseur_meteo", lambda: F.OpenMeteoMeteo(lecteur=ko))
    j = c.get("/").json()
    assert j["meteo"]["temperature_c"] == 12.0 and j["meteo_etat"]["etat"] == "perime" and j["meteo_etat"]["maj"] == 1.0


def test_meteo_desactivee(api):
    c, cfg = api
    cfg.meteo.enabled = False
    cfg.air.enabled = False
    j = c.get("/").json()
    assert j["meteo"] is None and j["meteo_etat"]["etat"] == "desactive" and j["air_etat"]["etat"] == "desactive"


def test_sans_localisation_la_carte_utilise_le_fuseau(api):
    c, cfg = api
    cfg.latitude = cfg.longitude = None
    cfg.nom_lieu = ""
    j = c.get("/").json()
    assert j["lieu"]["approximatif"] is True and j["lieu"]["nom"] == "Paris" and j["soleil"]["lever"]


def test_changement_de_fuseau(api, monkeypatch):
    c, cfg = api
    cfg.timezone = "America/Montreal"
    cfg.latitude = cfg.longitude = None
    cfg.nom_lieu = ""
    monkeypatch.setattr(main, "_maintenant", lambda: datetime(2026, 10, 6, 12, 31, 45, tzinfo=ZoneInfo("America/Montreal")))
    j = c.get("/").json()
    assert j["fuseau"]["decalage"] == "UTC-4" and j["lieu"]["nom"] == "Montréal"


def test_decalage_demi_heure(api):
    assert main._decalage(datetime(2026, 1, 1, tzinfo=ZoneInfo("Asia/Kolkata"))) == ("UTC+5:30", 330)
    assert main._decalage(datetime(2026, 1, 1, tzinfo=ZoneInfo("UTC"))) == ("UTC", 0)


def test_saint_desactive(api):
    c, cfg = api
    cfg.saint.enabled = False
    assert c.get("/").json()["saints"] == []


def test_observations_creation_lecture_modification_suppression(api):
    c, _ = api
    r = c.post("/observations", json={"texte": "Ciel dégagé ce soir."})
    assert r.status_code == 201 and r.json()["texte"] == "Ciel dégagé ce soir."
    ident = r.json()["id"]
    assert c.get("/observations").json()["observations"][0]["id"] == ident
    assert c.get("/").json()["observations"][0]["texte"] == "Ciel dégagé ce soir."
    assert c.put(f"/observations/{ident}", json={"texte": "Quelques étoiles."}).json()["texte"] == "Quelques étoiles."
    assert c.delete(f"/observations/{ident}").status_code == 200
    assert c.get("/observations").json()["observations"] == []
    assert c.delete(f"/observations/{ident}").status_code == 404
    assert c.put("/observations/999", json={"texte": "x"}).status_code == 404


@pytest.mark.parametrize("corps", [{"texte": ""}, {"texte": "   "}, {"texte": "x" * 2001}, {}, {"texte": 5}])
def test_observation_invalide_refusee(api, corps):
    assert api[0].post("/observations", json=corps).status_code == 422


def test_observations_desactivees(api):
    c, cfg = api
    cfg.observations.enabled = False
    assert c.post("/observations", json={"texte": "x"}).status_code == 404
    assert c.get("/").json()["observations"] == []


def test_les_routes_mutantes_exigent_un_administrateur():
    main.app.dependency_overrides.clear()
    c = TestClient(main.app)
    for req in (c.post("/observations", json={"texte": "x"}), c.put("/observations/1", json={"texte": "x"}), c.delete("/observations/1")):
        assert req.status_code in (401, 403), req.status_code


def test_la_lecture_est_gardee_et_le_sante_est_publique(monkeypatch):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")              # surcharge de test prévue par secubox_core.auth
    main.app.dependency_overrides.clear()
    c = TestClient(main.app)
    assert c.get("/").status_code in (401, 403)
    assert c.get("/health").status_code == 200
