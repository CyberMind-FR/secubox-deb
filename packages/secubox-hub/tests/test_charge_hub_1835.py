# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Charge du hub dans l'agrégateur (#1835).

Toutes les 5 s, jour et nuit : deux `list-units` ; et un `is-active` à chaque
lecture de /boot_mode et /auth_mode. Un list-units par cycle, les états du
cycle réutilisés, et des boucles qui dorment quand personne ne lit.
"""
import asyncio
import importlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")
from secubox_core.health import parse_units  # noqa: E402

TOUTES = """secubox-hub.service       loaded    active   running Hub
secubox-dpi.service       loaded    inactive dead    DPI
secubox-waf.service       loaded    failed   failed  WAF
secubox-kiosk.service     loaded    active   running Kiosk
secubox-vieux.service     not-found inactive dead    secubox-vieux.service
secubox-veille.service    loaded    active   exited  Veille
secubox-cache-warm@x.timer loaded   active   waiting Minuterie
secubox-boot.service      loaded    activating start Boot
"""
# Ce que rendait `list-units --type=service --state=running,failed,inactive`.
ATTENDU = """secubox-hub.service       loaded    active   running Hub
secubox-dpi.service       loaded    inactive dead    DPI
secubox-waf.service       loaded    failed   failed  WAF
secubox-kiosk.service     loaded    active   running Kiosk
secubox-vieux.service     not-found inactive dead    secubox-vieux.service
"""


@pytest.fixture
def lancements(monkeypatch):
    vus = []

    def faux_run(args, **kw):
        vus.append(list(args))
        if args[:2] == ["systemctl", "list-units"]:
            return subprocess.CompletedProcess(args, 0, TOUTES, "")
        return subprocess.CompletedProcess(args, 0, "inactive\n", "")

    monkeypatch.setattr(subprocess, "run", faux_run)
    monkeypatch.setattr(main, "_socket_ecoute", lambda p: False)
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: set())
    for k in ("units_brut", "etats_units"):
        main._cache.pop(k, None)
    main._cache["units_ts"] = 0
    return vus


def test_filtre_equivaut_au_list_units_du_releve():
    assert parse_units(main._filtre_etats_batch(TOUTES)) == parse_units(ATTENDU)


def test_un_seul_list_units_par_cycle(lancements):
    main._refresh_services_cache()
    main._refresh_health_batch()
    assert sum(1 for a in lancements if a[:2] == ["systemctl", "list-units"]) == 1
    mods = main._cache["health_batch"]["modules"]
    assert mods["hub"]["status"] == "ok" and mods["waf"]["status"] == "error"
    assert "veille" not in mods          # active/exited : hors du relevé, comme avant


def test_releve_sans_cycle_frais_fait_son_appel(lancements):
    main._refresh_health_batch()
    assert [a[:2] for a in lancements] == [["systemctl", "list-units"]]
    assert "--state=running,failed,inactive" in lancements[0]


def test_boot_et_auth_lisent_le_cycle(lancements):
    main._refresh_services_cache()
    n = len(lancements)
    assert main.boot_mode(user=None)["kiosk_running"] is True
    assert main.auth_mode(user=None)["zkp_running"] is False
    assert len(lancements) == n           # aucun is-active relancé


def test_boot_mode_sans_cycle_interroge_systemd(lancements):
    main.boot_mode(user=None)
    assert ["systemctl", "is-active", "secubox-kiosk"] in lancements


def test_boucles_dorment_sans_lecteur(monkeypatch):
    async def scenario():
        main._reveil = asyncio.Event()
        main._derniere_demande = time.time() - main.REPOS_S - 1
        attente = asyncio.create_task(main._attend_lecteur(0))
        await asyncio.sleep(0.05)
        endormie = not attente.done()
        main._marque_demande()                      # une requête arrive
        await asyncio.wait_for(attente, 1)
        # Lecteur récent : la pause seule, pas d'attente.
        await asyncio.wait_for(main._attend_lecteur(0), 1)
        return endormie

    try:
        assert asyncio.run(scenario()) is True
    finally:
        main._reveil = None


def test_middleware_marque_la_demande_meme_monte(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    monkeypatch.setattr(main, "_ensure_bg", lambda: None)
    main._derniere_demande = 0.0
    parent = FastAPI()
    parent.mount("/api/v1/hub", main.app)
    TestClient(parent).get("/api/v1/hub/inexistant")
    assert time.time() - main._derniere_demande < 5
