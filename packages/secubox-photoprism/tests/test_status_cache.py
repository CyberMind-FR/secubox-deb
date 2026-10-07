# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""/status ne recompte jamais la photothèque à chaque appel : la carte du Hall l'interroge chaque minute, et le comptage
(rglob + du sur toute la bibliothèque) tournait dans la boucle de l'agrégateur."""
import threading
import time

import pytest

from api import main as m


@pytest.fixture(autouse=True)
def _remise_a_zero():
    m._STATS.update(valeur=None, date=0.0, en_cours=False)
    yield
    m._STATS.update(valeur=None, date=0.0, en_cours=False)


def _faux(compteur, delai=0.0, valeur=None):
    def f():
        compteur.append(1)
        time.sleep(delai)
        return valeur or {"total_photos": 12, "total_videos": 3, "total_albums": 2, "storage_used": "1.2G", "import_pending": 0}
    return f


def _attend(cond, t=3.0):
    fin = time.time() + t
    while time.time() < fin:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_le_premier_appel_ne_bloque_pas_et_le_comptage_se_fait_en_arriere_plan(monkeypatch):
    n = []
    monkeypatch.setattr(m, "get_library_stats", _faux(n, delai=0.3))
    debut = time.time()
    s = m.stats_bibliotheque()
    assert time.time() - debut < 0.2                       # rend tout de suite
    assert s["mesure_en_cours"] is True and s["total_photos"] == 0
    assert _attend(lambda: m._STATS["valeur"] is not None)
    s2 = m.stats_bibliotheque()
    assert s2["total_photos"] == 12 and s2["mesure_en_cours"] is False and len(n) == 1


def test_dans_le_delai_on_ne_recompte_pas(monkeypatch):
    n = []
    monkeypatch.setattr(m, "get_library_stats", _faux(n))
    m.stats_bibliotheque()
    assert _attend(lambda: m._STATS["valeur"] is not None)
    for _ in range(5):
        m.stats_bibliotheque()
    assert len(n) == 1


def test_apres_le_delai_on_rend_l_ancien_chiffre_et_on_rafraichit_une_seule_fois(monkeypatch):
    n = []
    monkeypatch.setattr(m, "get_library_stats", _faux(n, delai=0.2))
    m.stats_bibliotheque()
    assert _attend(lambda: m._STATS["valeur"] is not None)
    m._STATS["date"] -= m.STATS_DELAI_S + 1
    a = m.stats_bibliotheque()
    b = m.stats_bibliotheque()
    assert a["total_photos"] == 12 and b["total_photos"] == 12     # l'ancien chiffre, sans attendre
    assert _attend(lambda: len(n) == 2 and not m._STATS["en_cours"])
    assert len(n) == 2


def test_un_echec_du_comptage_ne_casse_pas_status(monkeypatch):
    def boum():
        raise RuntimeError("disque")
    monkeypatch.setattr(m, "get_library_stats", boum)
    s = m.stats_bibliotheque()
    assert s["total_photos"] == 0
    assert _attend(lambda: not m._STATS["en_cours"])
    assert m.stats_bibliotheque()["total_photos"] == 0


def test_status_n_est_plus_une_coroutine_qui_bloque_la_boucle():
    import inspect
    assert not inspect.iscoroutinefunction(m.status)
