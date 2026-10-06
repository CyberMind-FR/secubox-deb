# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Météo et qualité de l'air : abstraction, cache, hors-ligne — jamais d'erreur technique brute."""
import json
import time

import pytest

from api import fournisseurs as F

OM_METEO = {"current": {"temperature_2m": 14.2, "relative_humidity_2m": 71, "weather_code": 2, "wind_speed_10m": 11.0, "time": "2026-10-06T12:30"}}
OM_AIR = {"current": {"european_aqi": 28, "pm2_5": 6.1, "pm10": 9.0, "time": "2026-10-06T12:00"}}


def test_meteo_open_meteo_est_traduite_en_francais():
    m = F.OpenMeteoMeteo(lecteur=lambda url, delai: OM_METEO).obtenir(45.69, 5.91)
    assert m.temperature_c == 14.2 and m.condition == "Peu nuageux" and m.icone == "nuage-soleil"
    assert m.humidite == 71 and m.vent_kmh == 11.0


def test_codes_meteo_inconnus_donnent_une_condition_neutre():
    assert F.condition_wmo(999) == ("Conditions variables", "nuage")


def test_qualite_de_l_air_niveau_en_francais():
    a = F.OpenMeteoAir(lecteur=lambda url, delai: OM_AIR).obtenir(45.69, 5.91)
    assert a.indice == 28 and a.niveau == "Correct" and a.polluant_principal in ("PM2.5", "PM10", None)


@pytest.mark.parametrize("aqi,niveau", [(10, "Bon"), (20, "Bon"), (21, "Correct"), (45, "Moyen"), (65, "Médiocre"), (85, "Mauvais"), (150, "Très mauvais")])
def test_echelle_aqi(aqi, niveau):
    assert F.niveau_air(aqi) == niveau


def test_reponse_mal_formee_devient_indisponible():
    with pytest.raises(F.FournisseurIndisponible):
        F.OpenMeteoMeteo(lecteur=lambda url, delai: {"current": {}}).obtenir(1, 1)


def test_erreur_reseau_devient_indisponible_sans_fuite_technique():
    def boom(url, delai):
        raise OSError("Connection refused 10.0.0.1:443")
    with pytest.raises(F.FournisseurIndisponible) as e:
        F.OpenMeteoMeteo(lecteur=boom).obtenir(1, 1)
    assert "10.0.0.1" not in str(e.value)


def test_coordonnees_arrondies_dans_l_url():
    vus = []
    F.OpenMeteoMeteo(lecteur=lambda url, delai: vus.append(url) or OM_METEO).obtenir(45.693456, 5.912345)
    assert "latitude=45.69&" in vus[0] and "longitude=5.91&" in vus[0]     # pas de position précise vers l'extérieur


def test_cache_frais_n_appelle_pas_le_fournisseur(tmp_path):
    appels = []
    c = F.Cache(tmp_path / "c.json")
    f = lambda: appels.append(1) or {"v": 1}                     # noqa: E731
    r1 = c.obtenir("meteo", 900, f)
    r2 = c.obtenir("meteo", 900, f)
    assert appels == [1] and r1.etat == "frais" and r2.etat == "frais" and r2.donnees == {"v": 1}


def test_cache_perime_est_servi_quand_le_fournisseur_echoue(tmp_path):
    c = F.Cache(tmp_path / "c.json")
    c.obtenir("meteo", 900, lambda: {"v": 1}, maintenant=1000.0)
    def ko():
        raise F.FournisseurIndisponible("hors ligne")
    r = c.obtenir("meteo", 900, ko, maintenant=1000.0 + 5000)
    assert r.etat == "perime" and r.donnees == {"v": 1} and r.ts == 1000.0


def test_sans_cache_ni_reseau_donne_indisponible(tmp_path):
    c = F.Cache(tmp_path / "c.json")
    def ko():
        raise F.FournisseurIndisponible("hors ligne")
    r = c.obtenir("meteo", 900, ko)
    assert r.etat == "indisponible" and r.donnees is None


def test_le_cache_survit_a_un_redemarrage(tmp_path):
    F.Cache(tmp_path / "c.json").obtenir("air", 900, lambda: {"v": 2}, maintenant=50.0)
    r = F.Cache(tmp_path / "c.json").obtenir("air", 900, lambda: (_ for _ in ()).throw(F.FournisseurIndisponible("x")), maintenant=60.0)
    assert r.donnees == {"v": 2} and r.etat == "frais"


def test_fichier_de_cache_corrompu_est_ignore(tmp_path):
    (tmp_path / "c.json").write_text("{{{")
    r = F.Cache(tmp_path / "c.json").obtenir("meteo", 900, lambda: {"v": 3})
    assert r.donnees == {"v": 3}


def test_un_echec_recent_n_est_pas_reessaye_a_chaque_requete(tmp_path):
    appels = []
    c = F.Cache(tmp_path / "c.json")
    def ko():
        appels.append(1)
        raise F.FournisseurIndisponible("x")
    c.obtenir("meteo", 900, ko, maintenant=100.0)
    c.obtenir("meteo", 900, ko, maintenant=110.0)
    assert appels == [1]                                          # recul après échec : le réseau n'est pas martelé
