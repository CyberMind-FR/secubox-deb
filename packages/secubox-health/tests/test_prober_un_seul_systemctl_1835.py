# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Un seul systemctl par passage du prober (#1835).

Un `is-active` par socket faisait du prober le premier lanceur de systemctl
de gk2 (~310 en cinq minutes).
"""
import importlib.util
import subprocess
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "module_prober", Path(__file__).resolve().parents[1] / "src" / "module_prober.py")
mp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mp)

SHOW = """Id=secubox-hub.service
ActiveState=active

Id=secubox-dpi.service
ActiveState=inactive

Id=secubox-aggregator.service
ActiveState=active
"""


@pytest.fixture
def lancements(monkeypatch, tmp_path):
    vus = []

    def faux_run(args, **kw):
        vus.append(args)
        if args[:2] == ["systemctl", "show"]:
            return subprocess.CompletedProcess(args, 0, SHOW, "")
        return subprocess.CompletedProcess(args, 0, "active\n", "")

    monkeypatch.setattr(mp.subprocess, "run", faux_run)
    monkeypatch.setattr(mp, "SOCKET_DIR", tmp_path)
    monkeypatch.setattr(mp, "CACHE_FILE", tmp_path / "cache" / "modules.json")
    return vus


def test_etats_en_un_appel(lancements):
    etats = mp.check_systemd_states(["hub", "dpi", "aggregator", "absent"])
    assert etats == {"hub": True, "dpi": False, "aggregator": True, "absent": False}
    assert len(lancements) == 1
    assert lancements[0][:4] == ["systemctl", "show", "-p", "Id,ActiveState"]


def test_nom_invalide_hors_du_lot(lancements):
    etats = mp.check_systemd_states(["hub", "pas valide"])
    assert etats == {"hub": True, "pas valide": False}
    assert "secubox-pas valide.service" not in lancements[0]


def test_un_passage_complet_un_seul_systemctl(lancements, monkeypatch):
    for n in ("hub", "dpi", "aggregator"):
        (mp.SOCKET_DIR / f"{n}.sock").touch()
    monkeypatch.setattr(mp, "check_api_health", lambda s, h: (True, "ok"))
    modules = mp.discover_modules()
    etats = mp.check_systemd_states(list(modules))
    res = {n: mp.probe_module(n, c, etats[n]) for n, c in modules.items()}
    mp.write_snapshot(res)
    assert len(lancements) == 1
    assert res["hub"]["overall"] == "ok" and res["dpi"]["layers"]["systemd"]["status"] == "down"


def test_boucle_principale_passe_par_le_lot():
    import inspect
    src = inspect.getsource(mp.main_loop)
    assert "check_systemd_states" in src and "probe_module(name, cfg)" not in src
