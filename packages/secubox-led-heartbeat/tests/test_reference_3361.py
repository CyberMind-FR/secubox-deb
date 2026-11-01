# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Référence évolutive par tranche horaire (ref #3361). Le temps est toujours injecté."""
import calendar
import json
import os
import time

import pytest

import reference
from reference import Reference, tranche

# Lundi 2026-01-05 00:00 UTC
LUNDI = calendar.timegm((2026, 1, 5, 0, 0, 0))
JOUR = 86400
PAS = 300


@pytest.fixture(autouse=True)
def _fuseau_utc(monkeypatch):
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _nourrir(ref, cle, t0, duree, valeur, pas=PAS):
    """Observe `valeur` (nombre ou fonction du rang) toutes les `pas` secondes. Renvoie le dernier t."""
    t = t0
    i = 0
    while t < t0 + duree:
        ref.observer(cle, valeur(i) if callable(valeur) else valeur, t)
        t += pas
        i += 1
    return t - pas


def test_tranche_lundi_minuit_et_dimanche_23h():
    assert tranche(LUNDI) == 0
    assert tranche(LUNDI + 6 * JOUR + 23 * 3600 + 59) == 167
    assert tranche(LUNDI + 3600) == 1


def test_apprentissage_plafonne_a_activite():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 23 * 3600, 10.0)
    assert r.niveau("k", 1000.0, fin + PAS, 1.0) <= 1
    assert r.niveau("k", 1000.0, fin + PAS, 1.0) == 1


def test_niveaux_par_ecart_reduit():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 30 * JOUR, lambda i: 8.0 if i % 2 else 12.0)
    t = fin + PAS
    # moyenne ~10, dispersion ~2
    assert [r.niveau("k", v, t, 0.5) for v in (11, 13, 15, 17)] == [0, 1, 2, 3]


def test_plancher_box_calme():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 30 * JOUR, 0.0)
    t = fin + PAS
    assert r.niveau("k", 2.0, t, 5.0) == 0
    # z = 9/5 = 1,8 : « activité » (une valeur de 12 donnerait z = 2,4 : « attention »)
    assert r.niveau("k", 9.0, t, 5.0) == 1
    assert r.niveau("k", 12.0, t, 5.0) == 2


def test_attaque_soutenue_reste_visible():
    r = Reference()
    t0 = LUNDI
    fin = _nourrir(r, "k", t0, 30 * JOUR, 10.0)
    debut = t0 + 30 * JOUR
    assert fin + PAS == debut
    # une heure à 20 fois la normale ; on évalue avant d'observer, comme le fera l'appelant
    t = debut
    niveau = None
    while t < debut + 3600:
        niveau = r.niveau("k", 200.0, t, 5.0)
        r.observer("k", 200.0, t)
        t += PAS
    assert niveau >= 2


def test_hausse_durable_devient_normale():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 30 * JOUR, 10.0)
    fin = _nourrir(r, "k", fin + PAS, 21 * JOUR, 50.0)
    assert r.niveau("k", 50.0, fin + PAS, 5.0) == 0


def test_horloge_recule():
    r = Reference()
    t = LUNDI + 5 * JOUR
    r.observer("k", 10.0, t)
    r.observer("k", 12.0, t - 3600)
    r.observer("k", 11.0, t - 3600)
    n = r.niveau("k", 10.0, t - 3000, 1.0)
    assert n in (0, 1, 2, 3)
    assert r.niveau("k", 10.0, t - 3000, 0.0) in (0, 1, 2, 3)


def test_cle_inconnue_donne_none():
    assert Reference().niveau("rien", 1.0, LUNDI, 1.0) is None


def test_aller_retour_dict():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 10 * JOUR, lambda i: 8.0 if i % 2 else 12.0)
    d = json.loads(json.dumps(r.vers_dict()))
    r2 = Reference.depuis_dict(d)
    t = fin + PAS
    for v in (9, 11, 13, 15, 40):
        assert r2.niveau("k", v, t, 0.5) == r.niveau("k", v, t, 0.5)
    r2.observer("k", 10.0, t)  # reste utilisable


@pytest.mark.parametrize("d", [None, "x", 3, [], {}, {"version": 99}, {"version": 1, "cles": "x"},
                               {"version": 1, "cles": {"k": {"court": "oups"}}},
                               {"version": 1, "cles": {"k": {"premiere": float("nan")}}}])
def test_dict_invalide_repart_vide(d):
    r = Reference.depuis_dict(d)
    assert isinstance(r, Reference)
    assert r.niveau("k", 1.0, LUNDI, 1.0) is None
    r.observer("k", 1.0, LUNDI)


def test_saut_horloge_avant_reapprend():
    r = Reference()
    r.observer("k", 10.0, 1767225600 + 86400)
    r.observer("k", 10.0, LUNDI)
    assert r.niveau("k", 1e9, LUNDI + PAS, 1.0) <= 1


def test_saut_horloge_apres_historique_reapprend():
    r = Reference()
    fin = _nourrir(r, "k", LUNDI, 30 * JOUR, 10.0)
    assert r.niveau("k", 1e9, fin + PAS, 1.0) == 3
    r.observer("k", 10.0, fin + 10 * JOUR)
    assert r.niveau("k", 1e9, fin + 10 * JOUR, 1.0) <= 1


def test_date_implausible_ignoree():
    r = Reference()
    r.observer("k", 10.0, 86400)
    assert r.niveau("k", 10.0, 86400, 1.0) is None
    assert r.vers_dict()["cles"] == {}
    r.observer("k", 10.0, LUNDI)
    assert r.niveau("k", 10.0, 86400, 1.0) is None
