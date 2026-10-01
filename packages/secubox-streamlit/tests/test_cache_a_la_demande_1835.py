# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le cache se rafraîchit à la demande, pas en boucle (#1835).

Mesuré sur gk2 : la boucle relançait `streamlitctl app list` + `instance list`
toutes les 30 s (~400 processus chacun) et sondait le conteneur toutes les
5 s, pour aucune lecture de la journée — ~14 000 lancements en dix minutes."""
import asyncio
import threading

import pytest

from api import main


@pytest.fixture
def banc(monkeypatch):
    monkeypatch.setattr(main, "_cache", main.DoubleBufferCache())
    monkeypatch.setattr(main, "_VERROU_CACHE", None)
    appels = {"details": [], "instant": []}

    def details():
        appels["details"].append(threading.current_thread() is threading.main_thread())
        main._cache.set_details({"app_count": 3, "apps": [], "instances": [], "running_apps": 1,
                                 "instance_count": 0, "running_instances": 0,
                                 "container_status": "running", "use_lxc": True, "default_port": 8501})

    def instant():
        appels["instant"].append(threading.current_thread() is threading.main_thread())
        main._cache.set_instant({"container_status": "running"})
    monkeypatch.setattr(main, "_refresh_details_cache", details)
    monkeypatch.setattr(main, "_refresh_instant_cache", instant)
    return appels


def test_aucune_boucle_permanente(banc):
    assert not hasattr(main, "_cache_refresh_loop")

    async def go():
        await main.startup_cache()
        await main._cache_task
        await asyncio.sleep(0.05)
    asyncio.run(go())
    assert len(banc["details"]) == 1 and banc["instant"] == []   # un seul pré-remplissage


def test_pas_de_rafraichissement_tant_que_frais(banc):
    async def go():
        await main.details()
        await main.details()
        await main.status()
    asyncio.run(go())
    assert len(banc["details"]) == 1


def test_un_seul_rafraichissement_pour_des_requetes_simultanees(banc):
    async def go():
        await asyncio.gather(*(main.details() for _ in range(6)))
    asyncio.run(go())
    assert len(banc["details"]) == 1


def test_le_rafraichissement_sort_de_la_boucle(banc):
    asyncio.run(main.instant())
    assert banc["instant"] == [False], "un appel synchrone dans la boucle fige l'API"


def test_perime_mais_present_repond_tout_de_suite_puis_rafraichit(banc, monkeypatch):
    """Une liste fraîche coûte ~9 s sur gk2 : on rend l'ancienne aussitôt et
    on rafraîchit en tâche de fond ; on n'attend que s'il n'y a rien."""
    monkeypatch.setattr(main, "_EN_FOND", {})

    async def go():
        await main.details()                                   # rien : on attend
        assert len(banc["details"]) == 1
        main._cache._details_ts = 0                            # périmé
        r = await main.details()                               # présent : réponse immédiate
        assert r["app_count"] == 3 and len(banc["details"]) == 1
        await asyncio.gather(*main._EN_FOND.values())          # le fond rafraîchit
        assert len(banc["details"]) == 2
    asyncio.run(go())
