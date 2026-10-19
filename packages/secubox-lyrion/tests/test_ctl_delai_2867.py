# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2867 — la page /lyrion/ ne tombe plus en HTTP 500 quand `lyrionctl` est lent.

Constat sur gk2 (charge 10 à 12) : `lyrionctl status` sous `secubox` met 9 s ; la page lance 4 lectures en parallèle ; au-delà de 15 s `subprocess.TimeoutExpired`
n'était pas attrapée -> HTTP 500 (« Lecture incomplète — état : HTTP 500 ; composants : HTTP 500 »)."""
import subprocess
import threading
import time
from unittest import mock

import pytest
from fastapi import HTTPException

import secubox_core.config as _cfg

# `api.main` lit la config et crée des répertoires À L'IMPORT : on isole la machine (comme les autres modules).
_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main as M  # noqa: E402


@pytest.fixture(autouse=True)
def cache_vide():
    M._CACHE_CTL.clear()
    yield
    M._CACHE_CTL.clear()


def test_un_delai_depasse_est_un_504_explicite_et_non_un_500(monkeypatch):
    def lent(*a, **k):
        raise subprocess.TimeoutExpired(cmd="lyrionctl", timeout=25)
    monkeypatch.setattr(M.subprocess, "check_output", lent)
    with pytest.raises(HTTPException) as e:
        M._ctl_json("status")
    assert e.value.status_code == 504 and "délai" in e.value.detail.lower()


def test_le_delai_reste_sous_celui_du_proxy(monkeypatch):
    vus = {}

    def faux(cmd, **k):
        vus.update(k)
        return b'{"overall": "green"}'
    monkeypatch.setattr(M.subprocess, "check_output", faux)
    assert M._ctl_json("status") == {"overall": "green"} and vus["timeout"] == 25


def test_deux_lectures_proches_n_executent_ctl_qu_une_fois(monkeypatch):
    n = []
    monkeypatch.setattr(M.subprocess, "check_output", lambda *a, **k: n.append(1) or b'{"a": 1}')
    assert M._ctl_json("status") == M._ctl_json("status") == {"a": 1} and len(n) == 1


def test_le_cache_expire(monkeypatch):
    n = []
    monkeypatch.setattr(M.subprocess, "check_output", lambda *a, **k: n.append(1) or b'{"a": 1}')
    horloge = [1000.0]
    monkeypatch.setattr(M.time, "monotonic", lambda: horloge[0])
    M._ctl_json("status")
    horloge[0] += M.TTL_CTL + 1
    M._ctl_json("status")
    assert len(n) == 2


def test_un_echec_n_est_jamais_memorise(monkeypatch):
    appels = []

    def tantot(*a, **k):
        appels.append(1)
        if len(appels) == 1:
            raise subprocess.TimeoutExpired(cmd="x", timeout=45)
        return b'{"overall": "green"}'
    monkeypatch.setattr(M.subprocess, "check_output", tantot)
    with pytest.raises(HTTPException):
        M._ctl_json("status")
    assert M._ctl_json("status") == {"overall": "green"}          # le 2e appel retente : un échec ne devient pas « l'état »


def test_lectures_concurrentes_une_seule_execution(monkeypatch):
    n = []

    def lent(*a, **k):
        n.append(1)
        time.sleep(0.2)
        return b'{"a": 1}'
    monkeypatch.setattr(M.subprocess, "check_output", lent)
    sortie = []
    fils = [threading.Thread(target=lambda: sortie.append(M._ctl_json("status"))) for _ in range(5)]
    [f.start() for f in fils]
    [f.join() for f in fils]
    assert len(n) == 1 and sortie == [{"a": 1}] * 5


def test_une_action_vide_le_cache():
    M._CACHE_CTL[("status",)] = (time.monotonic(), {"a": 1})
    M._invalider_cache_ctl()
    assert not M._CACHE_CTL


def test_si_ctl_echoue_la_derniere_lecture_connue_est_servie_marquee_obsolete(monkeypatch):
    """Sous charge, le proxy coupe à 30 s : plutôt qu'une page vide, la dernière lecture réussie (≤ 15 min), marquée obsolète."""
    horloge = [1000.0]
    monkeypatch.setattr(M.time, "monotonic", lambda: horloge[0])
    monkeypatch.setattr(M.subprocess, "check_output", lambda *a, **k: b'{"overall": "green"}')
    assert M._ctl_json("status") == {"overall": "green"}
    horloge[0] += M.TTL_CTL + 5

    def lent(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=25)
    monkeypatch.setattr(M.subprocess, "check_output", lent)
    r = M._ctl_json("status")
    assert r["overall"] == "green" and r["obsolete"] is True and r["age_s"] >= M.TTL_CTL


def test_une_lecture_trop_ancienne_n_est_plus_servie(monkeypatch):
    horloge = [1000.0]
    monkeypatch.setattr(M.time, "monotonic", lambda: horloge[0])
    monkeypatch.setattr(M.subprocess, "check_output", lambda *a, **k: b'{"overall": "green"}')
    M._ctl_json("status")
    horloge[0] += M.AGE_MAX_OBSOLETE + 1

    def lent(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=25)
    monkeypatch.setattr(M.subprocess, "check_output", lent)
    with pytest.raises(HTTPException) as e:
        M._ctl_json("status")
    assert e.value.status_code == 504
