# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3708 : une rafale de connexions ne remplit ni la mémoire ni les fils, et le propriétaire passe."""
import threading
import time

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
