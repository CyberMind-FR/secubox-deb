# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3708 : une rafale de connexions ne remplit ni la mémoire ni les fils, et le propriétaire passe."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from secubox_core.porte_argon2 import Porte, Saturee


def _occupe(porte, adresse, confiance, lache, n=1):
    prets = []
    for i in range(n):
        pret = threading.Event()

        def f(a=adresse.format(i), p=pret):
            with porte.passage(a, confiance):
                p.set()
                lache.wait(10)
        threading.Thread(target=f, daemon=True).start()
        prets.append(pret)
    return prets


def test_rafale_internet_bornee_et_lan_servi():
    porte, lache = Porte(attente_max=4, delai=0.3), threading.Event()
    prets = _occupe(porte, "203.0.113.{}", False, lache, n=2)
    assert all(p.wait(2) for p in prets)
    refus = []

    def wan(i):
        try:
            with porte.passage(f"198.51.100.{i}", False):
                refus.append(0)
        except Saturee as e:
            refus.append(e.statut)
    fils = [threading.Thread(target=wan, args=(i,)) for i in range(30)]
    t = time.monotonic()
    [f.start() for f in fils]
    with porte.passage("192.168.1.10", True):             # le propriétaire passe PENDANT la rafale
        assert time.monotonic() - t < 1.0
    [f.join() for f in fils]
    assert refus == [503] * 30 and porte._attente == {True: 0, False: 0}
    lache.set()


def test_une_source_ne_tient_pas_toutes_les_places():
    porte, lache = Porte(), threading.Event()
    prets = _occupe(porte, "192.168.1.66", True, lache, n=2)
    assert all(p.wait(2) for p in prets)
    with pytest.raises(Saturee) as e:
        with porte.passage("192.168.1.66", True):
            pass
    assert e.value.statut == 429
    with porte.passage("192.168.1.10", True):
        pass
    lache.set()


def test_ipv6_par_64_et_compteur_qui_ne_grossit_pas():
    porte = Porte(par_source=1)
    with porte.passage("2001:db8::1", False):
        with pytest.raises(Saturee):
            with porte.passage("2001:db8::2", False):
                pass
        with porte.passage("2001:db8:0:1::1", False):
            pass
    for i in range(50):
        with porte.passage(f"203.0.113.{i}", False):
            pass
    assert porte._sources == {} and porte._cours == {True: 0, False: 0}


def test_en_attente_passe_quand_une_place_se_libere():
    porte, lache = Porte(delai=5), threading.Event()
    prets = _occupe(porte, "203.0.113.{}", False, lache, n=2)
    assert all(p.wait(2) for p in prets)
    threading.Timer(0.2, lache.set).start()
    with porte.passage("198.51.100.1", False):
        pass


def test_une_exception_rend_la_place():
    porte = Porte(total=1, hors_zone=1)
    for _ in range(3):
        with pytest.raises(RuntimeError):
            with porte.passage("203.0.113.1", False):
                raise RuntimeError


def test_rafale_sur_la_connexion_historique_le_lan_passe(monkeypatch):
    """R3 : l'exécuteur par défaut, non borné et AVANT la porte, faisait attendre le propriétaire 13 s."""
    import asyncio

    from fastapi import HTTPException, Response
    from secubox_core import auth, porte_argon2

    monkeypatch.setattr(porte_argon2, "PORTE", Porte(attente_max=8, delai=2.0))
    monkeypatch.setattr(auth, "_check_password", lambda u, p: time.sleep(0.3) or False)
    monkeypatch.setattr(auth, "_requete_lan", lambda r: r == "lan")
    monkeypatch.setattr(auth, "adresse_client", lambda r: r)
    monkeypatch.setattr(auth, "_emit_session_event", lambda *a: None)

    class Req(str):
        headers = {}

    async def entre(source):
        try:
            await auth.login(auth.LoginRequest(username="x", password="y"), Req(source), Response())
        except HTTPException as e:
            return e.status_code

    async def scene():
        # Exécuteur par défaut d'un ARM à 4 cœurs : 8 fils.
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(8))
        rafale = [asyncio.create_task(entre(f"198.51.100.{i}")) for i in range(200)]
        await asyncio.sleep(0.05)
        t = time.monotonic()
        assert await entre("lan") == 401
        duree = time.monotonic() - t
        return duree, await asyncio.gather(*rafale)
    duree, codes = asyncio.run(scene())
    assert duree < 1.0, duree
    assert codes.count(503) >= 180 and set(codes) <= {401, 503}


def test_places_reservees_sans_fil_puis_rendues():
    porte = Porte(attente_max=2)
    t1, t2 = porte.reserver("203.0.113.1", False), porte.reserver("203.0.113.2", False)
    with pytest.raises(Saturee):
        porte.reserver("203.0.113.3", False)
    for t in (t1, t2):
        with porte.tenir(t):
            pass
    assert porte._sources == {} and porte._attente == {True: 0, False: 0} == porte._cours
