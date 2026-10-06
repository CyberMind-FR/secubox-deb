# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le catalogue vient de la minuterie, pas d'une boucle ; un seul systemctl (#1835).

Sur gk2, la boucle de 60 s lançait ~290 `systemctl` toutes les cinq minutes
(cinq par service) en plus de la minuterie qui faisait déjà le travail.
"""
import asyncio
import json
import os
import time

import pytest

from api import main as m

SHOW = """Id=secubox-hub.service
LoadState=loaded
UnitFileState=enabled
ActiveState=active
ActiveEnterTimestamp=Thu 2026-10-01 10:00:00 CEST
MemoryCurrent=52428800

Id=secubox-dpi.service
LoadState=loaded
UnitFileState=disabled
ActiveState=inactive
ActiveEnterTimestamp=
MemoryCurrent=[not set]

Id=secubox-absent.service
LoadState=not-found
UnitFileState=
ActiveState=inactive
ActiveEnterTimestamp=
MemoryCurrent=[not set]
"""


@pytest.fixture
def appels(monkeypatch, tmp_path):
    """Compte les systemctl lancés ; le cache vit dans tmp_path."""
    vus = []

    def faux(args, timeout=10):
        vus.append(args)
        return {"success": True, "stdout": SHOW.strip(), "stderr": ""}

    monkeypatch.setattr(m, "_run_systemctl", faux)
    monkeypatch.setattr(m, "CACHE_FILE", tmp_path / "catalog.json")
    monkeypatch.setattr(m, "_cache", {})
    monkeypatch.setattr(m, "_cle_fichier", None)
    monkeypatch.setattr(m, "_last_refresh", None)
    monkeypatch.setattr(m, "_en_fond", None)
    monkeypatch.setattr(m, "_verrou_refresh", asyncio.Lock())
    return vus


def test_un_seul_show_pour_tout_le_catalogue(appels):
    services = m._discover_services()
    assert len(services) == len(m.KNOWN_SERVICES)
    assert len(appels) == 1, appels
    assert appels[0][:3] == ["show", "-p", m._PROPRIETES]
    par_nom = {s.name: s for s in services}
    hub, dpi = par_nom["secubox-hub"], par_nom["secubox-dpi"]
    assert (hub.status, hub.enabled, hub.memory_usage) == ("running", True, "50.0 MB")
    assert hub.active_since == "Thu 2026-10-01 10:00:00 CEST"
    assert (dpi.status, dpi.enabled, dpi.memory_usage, dpi.active_since) == ("stopped", False, None, None)
    # Absent de la sortie : non installé, comme quand `systemctl cat` échouait.
    assert par_nom["secubox-qos"].installed is False


def test_unite_absente_non_installee(appels):
    st = m._get_service_status("secubox-absent")
    assert st == {"installed": False, "enabled": False, "status": "not_installed",
                  "active_since": None, "memory_usage": None}
    assert len(appels) == 1


def test_plus_de_boucle_au_demarrage():
    noms = [getattr(f, "__name__", "") for f in m.app.router.on_startup]
    assert "startup" not in noms and not hasattr(m, "_background_refresh")


def test_catalogue_de_la_minuterie_sans_systemctl(appels):
    m.CACHE_FILE.write_text(json.dumps({"services": [{"name": "secubox-hub"}], "stats": {}}))
    cat = asyncio.run(m._catalogue_frais())
    assert cat["services"] == [{"name": "secubox-hub"}]
    assert appels == []
    # La minuterie réécrit : relu au passage suivant, toujours sans systemctl.
    m.CACHE_FILE.write_text(json.dumps({"services": [{"name": "secubox-dpi"}], "stats": {}}))
    os.utime(m.CACHE_FILE, ns=(time.time_ns(), time.time_ns() + 1_000_000))
    assert asyncio.run(m._catalogue_frais())["services"] == [{"name": "secubox-dpi"}]
    assert appels == []


def test_perime_servi_tout_de_suite_puis_recalcule_une_fois(appels):
    m.CACHE_FILE.write_text(json.dumps({"services": [{"name": "ancien"}], "stats": {}}))
    vieux = time.time() - m.PERIME_S - 60
    os.utime(m.CACHE_FILE, (vieux, vieux))

    async def scenario():
        a = await m._catalogue_frais()
        b = await m._catalogue_frais()       # pendant le calcul : pas un second
        servis = (a["services"], b["services"])
        await m._en_fond
        return servis

    servis = asyncio.run(scenario())
    assert servis == ([{"name": "ancien"}], [{"name": "ancien"}])
    assert len(appels) == 1
    assert len(m._cache["services"]) == len(m.KNOWN_SERVICES)
    assert json.loads(m.CACHE_FILE.read_text())["stats"]["total_services"] == len(m.KNOWN_SERVICES)


def test_sans_fichier_le_premier_appel_attend(appels):
    cat = asyncio.run(m._catalogue_frais())
    assert len(cat["services"]) == len(m.KNOWN_SERVICES) and len(appels) == 1
