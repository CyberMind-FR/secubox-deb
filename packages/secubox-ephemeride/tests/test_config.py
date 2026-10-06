# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Configuration et localisation : explicite d'abord, puis repli par fuseau, jamais d'exigence de géolocalisation précise."""
from api import config


def charge(tmp_path, texte):
    f = tmp_path / "e.toml"
    f.write_text(texte)
    return config.charger(f, defaut=tmp_path / "absent.toml")


def test_defauts_sans_fichier(tmp_path):
    c = config.charger(tmp_path / "rien.toml", defaut=tmp_path / "rien2.toml")
    assert c.enabled and c.timezone == "Europe/Paris" and c.meteo.enabled and c.observations.enabled


def test_lieu_explicite(tmp_path):
    c = charge(tmp_path, '[ephemeride]\ntimezone="Europe/Paris"\n[ephemeride.location]\nname="Aix-les-Bains"\nlatitude=45.69\nlongitude=5.91\n')
    l = c.lieu()
    assert (l.nom, l.latitude, l.longitude, l.approximatif) == ("Aix-les-Bains", 45.69, 5.91, False)


def test_repli_sur_la_ville_du_fuseau_marque_approximatif(tmp_path):
    l = charge(tmp_path, '[ephemeride]\ntimezone="Europe/London"\n').lieu()
    assert l.approximatif is True and abs(l.latitude - 51.5) < 0.2


def test_coordonnees_invalides_ignorees(tmp_path):
    l = charge(tmp_path, '[ephemeride]\n[ephemeride.location]\nlatitude=123\nlongitude=5\n').lieu()
    assert l.approximatif is True


def test_fuseau_inconnu_retombe_sur_paris(tmp_path):
    c = charge(tmp_path, '[ephemeride]\ntimezone="Mars/Olympus"\n')
    assert c.fuseau().key == "Europe/Paris"


def test_toml_corrompu_donne_les_defauts(tmp_path):
    c = charge(tmp_path, "[[[pas du toml")
    assert c.enabled and c.timezone == "Europe/Paris"


def test_fonctions_desactivables(tmp_path):
    c = charge(tmp_path, "[ephemeride]\nenabled=true\n[ephemeride.weather]\nenabled=false\n[ephemeride.air_quality]\nenabled=false\n"
                         "[ephemeride.saint]\nenabled=false\n[ephemeride.observations]\nenabled=false\n")
    assert not (c.meteo.enabled or c.air.enabled or c.saint.enabled or c.observations.enabled)
