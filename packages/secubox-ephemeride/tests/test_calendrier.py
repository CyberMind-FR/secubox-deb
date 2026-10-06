# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Calendrier : date, semaine ISO, jour de l'année, saison — transitions de jour, mois, année, bissextile."""
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from api import calendrier

PARIS = ZoneInfo("Europe/Paris")


def d(y, m, j, h=12, tz=PARIS):
    return datetime(y, m, j, h, tzinfo=tz)


def test_le_6_octobre_2026():
    c = calendrier.infos(d(2026, 10, 6))
    assert (c.jour_semaine, c.jour, c.mois, c.annee) == ("mardi", 6, "octobre", 2026)
    assert c.semaine_iso == 41 and c.jour_annee == 279
    assert c.saison == "automne" and c.saison_debut.isoformat() == "2026-09-22"
    assert c.jours_avant_saison_suivante == 76 and c.saison_suivante == "hiver"


def test_changement_de_jour_a_minuit_local():
    assert calendrier.infos(d(2026, 10, 6, 23)).jour == 6
    assert calendrier.infos(d(2026, 10, 7, 0)).jour == 7


def test_changement_de_mois():
    assert calendrier.infos(d(2026, 1, 31)).mois == "janvier"
    assert calendrier.infos(d(2026, 2, 1)).mois == "février" and calendrier.infos(d(2026, 2, 1)).jour_annee == 32


def test_changement_d_annee_et_semaine_iso_53():
    fin = calendrier.infos(d(2026, 12, 31))
    assert fin.jour_annee == 365 and fin.annee == 2026
    debut = calendrier.infos(d(2027, 1, 1))
    assert debut.jour_annee == 1 and debut.annee == 2027 and debut.semaine_iso == 53   # ISO : la semaine appartient à 2026


def test_annee_bissextile():
    assert calendrier.infos(d(2028, 2, 29)).jour_annee == 60
    assert calendrier.infos(d(2028, 12, 31)).jour_annee == 366


@pytest.mark.parametrize("m,j,saison", [(3, 19, "hiver"), (3, 20, "printemps"), (6, 20, "printemps"), (6, 21, "été"),
                                         (9, 21, "été"), (9, 22, "automne"), (12, 20, "automne"), (12, 21, "hiver"),
                                         (1, 1, "hiver")])
def test_saisons_hemisphere_nord(m, j, saison):
    assert calendrier.infos(d(2026, m, j)).saison == saison


def test_hemisphere_sud_inverse_les_saisons():
    assert calendrier.infos(d(2026, 10, 6), latitude=-33.9).saison == "printemps"
    assert calendrier.infos(d(2026, 1, 15), latitude=-33.9).saison == "été"


def test_jours_avant_la_saison_suivante_traverse_le_nouvel_an():
    c = calendrier.infos(d(2026, 12, 25))
    assert c.saison == "hiver" and c.saison_suivante == "printemps"
    assert c.jours_avant_saison_suivante == 85        # 25 déc 2026 → 20 mars 2027


def test_le_fuseau_decide_du_jour():
    # 23:30 UTC le 6 octobre = 01:30 le 7 à Paris
    from datetime import timezone
    assert calendrier.infos(datetime(2026, 10, 6, 23, 30, tzinfo=timezone.utc).astimezone(PARIS)).jour == 7
