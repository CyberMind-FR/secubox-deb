# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Moteur astronomique local (aucun réseau) : soleil, lune, phases, transitions de jour."""
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from api import astro

LONDRES = (51.5074, -0.1278)
PARIS = (48.8566, 2.3522)
TROMSO = (69.6492, 18.9553)


def local(y, m, d, h=0, mi=0, tz="Europe/Paris"):
    return datetime(y, m, d, h, mi, tzinfo=ZoneInfo(tz))


def minutes(dt, ref):
    return abs((dt - ref).total_seconds()) / 60


def test_soleil_londres_solstice_d_ete():
    s = astro.soleil(local(2026, 6, 21, 12, tz="Europe/London"), *LONDRES)
    assert minutes(s.lever, local(2026, 6, 21, 4, 43, "Europe/London")) <= 6
    assert minutes(s.coucher, local(2026, 6, 21, 21, 21, "Europe/London")) <= 6
    assert 16.3 < s.duree.total_seconds() / 3600 < 16.9


def test_equinoxe_jour_et_nuit_presque_egaux():
    s = astro.soleil(local(2026, 3, 20, 12, tz="UTC"), 0.0, 0.0)
    assert 11.9 < s.duree.total_seconds() / 3600 < 12.3


def test_les_heures_suivent_le_fuseau_et_l_heure_d_ete():
    ete = astro.soleil(local(2026, 7, 1, 12), *PARIS)
    hiver = astro.soleil(local(2026, 12, 1, 12), *PARIS)
    assert ete.lever.utcoffset() == timedelta(hours=2)
    assert hiver.lever.utcoffset() == timedelta(hours=1)
    assert ete.lever.hour < 7 and hiver.lever.hour >= 8


def test_passage_heure_d_ete_le_jour_du_changement():
    # 2026-03-29 : 02:00 → 03:00, la journée locale ne dure que 23 h ; rien ne doit casser
    s = astro.soleil(local(2026, 3, 29, 12), *PARIS)
    assert s.lever.date() == date(2026, 3, 29) and s.coucher.date() == date(2026, 3, 29)
    assert s.lever < s.coucher


def test_etat_avant_lever_pendant_apres_coucher():
    midi = astro.soleil(local(2026, 10, 6, 12), *PARIS)
    assert midi.etat == "jour" and 0.3 < midi.progression < 0.7
    assert astro.soleil(local(2026, 10, 6, 3), *PARIS).etat == "avant_lever"
    assert astro.soleil(local(2026, 10, 6, 3), *PARIS).progression == 0.0
    assert astro.soleil(local(2026, 10, 6, 23), *PARIS).etat == "apres_coucher"
    assert astro.soleil(local(2026, 10, 6, 23), *PARIS).progression == 1.0


def test_jour_polaire_et_nuit_polaire():
    ete = astro.soleil(local(2026, 6, 21, 12), *TROMSO)
    assert ete.etat == "jour_polaire" and ete.lever is None and ete.coucher is None
    assert ete.duree == timedelta(hours=24) and ete.progression == pytest.approx(0.5, abs=0.5)
    hiver = astro.soleil(local(2026, 12, 21, 12), *TROMSO)
    assert hiver.etat == "nuit_polaire" and hiver.duree == timedelta(0) and hiver.progression == 0.0


NOUVELLES_LUNES_2026 = [(1, 18), (2, 17), (3, 19), (4, 17), (5, 16), (6, 15), (7, 14), (8, 12), (9, 11), (10, 10), (11, 9), (12, 9)]
PLEINES_LUNES_2026 = [(1, 3), (2, 1), (3, 3), (4, 2), (5, 1), (5, 31), (6, 29), (7, 29), (8, 28), (9, 26), (10, 26), (11, 24), (12, 24)]


@pytest.mark.parametrize("m,j", NOUVELLES_LUNES_2026)
def test_la_nouvelle_lune_tombe_le_bon_jour(m, j):
    veille = datetime(2026, m, j, tzinfo=timezone.utc) - timedelta(days=3)
    nxt = astro.prochaine_phase(veille)
    assert nxt.nom == "Nouvelle lune"
    assert abs((nxt.quand - datetime(2026, m, j, 12, tzinfo=timezone.utc)).total_seconds()) < 36 * 3600


@pytest.mark.parametrize("m,j", PLEINES_LUNES_2026)
def test_la_pleine_lune_tombe_le_bon_jour(m, j):
    veille = datetime(2026, m, j, tzinfo=timezone.utc) - timedelta(days=3)
    nxt = astro.prochaine_phase(veille)
    assert nxt.nom == "Pleine lune"
    assert abs((nxt.quand - datetime(2026, m, j, 12, tzinfo=timezone.utc)).total_seconds()) < 36 * 3600


def test_lune_le_6_octobre_2026_dernier_croissant():
    l = astro.lune(local(2026, 10, 6, 12), *PARIS)
    assert l.nom == "Dernier croissant" and l.croissante is False
    assert 5 < l.illumination < 30
    assert 25 < l.age_jours < 29.6
    assert astro.prochaine_phase(local(2026, 10, 6, 12)).nom == "Nouvelle lune"


def test_illumination_pleine_et_nouvelle():
    pleine = astro.lune(datetime(2026, 9, 26, 15, tzinfo=timezone.utc), *PARIS)
    assert pleine.illumination > 97 and pleine.nom == "Pleine lune"
    nouvelle = astro.lune(datetime(2026, 10, 10, 12, tzinfo=timezone.utc), *PARIS)
    assert nouvelle.illumination < 3 and nouvelle.nom == "Nouvelle lune"


def test_lune_lever_coucher_dans_la_journee_ou_aucun():
    l = astro.lune(local(2026, 10, 6, 12), *PARIS)
    for t in (l.lever, l.coucher):
        assert t is None or t.date() == date(2026, 10, 6)


def test_moment_naif_refuse():
    with pytest.raises(ValueError):
        astro.soleil(datetime(2026, 10, 6, 12), *PARIS)
