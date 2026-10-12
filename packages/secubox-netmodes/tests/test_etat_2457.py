# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2457 — netmodes ne prétend pas connaître le mode : sans état enregistré, « inconnu » (et non « router » inventé) ; WAN lu dans la table de routage."""
import asyncio
import json
from unittest import mock

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main  # noqa: E402


def test_sans_fichier_d_etat_le_mode_est_inconnu(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "absent.json")
    s = main._state()
    assert s["current_mode"] is None and s["last_change"] is None
    assert asyncio.run(main.get_current_mode(user={})) == {"mode": None, "inconnu": True}


def test_mode_enregistre_est_rendu_avec_sa_description(tmp_path, monkeypatch):
    f = tmp_path / "s.json"; f.write_text(json.dumps({"current_mode": "relay", "pending_mode": None, "last_change": "2026-10-12T10:00:00"}))
    monkeypatch.setattr(main, "STATE_FILE", f)
    r = asyncio.run(main.get_current_mode(user={}))
    assert r["mode"] == "relay" and r["name"] and "inconnu" not in r


def test_wan_lu_dans_la_route_par_defaut(monkeypatch):
    sortie = json.dumps([{"dst": "default", "gateway": "192.0.2.1", "dev": "eth2", "metric": 100}, {"dst": "default", "gateway": "198.51.100.1", "dev": "wg0", "metric": 600}])
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": sortie, "returncode": 0})())
    assert main._route_defaut() == {"interface": "eth2", "passerelle": "192.0.2.1"}      # la route de plus petite métrique
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("pas de ip")))
    assert main._route_defaut() == {"interface": None, "passerelle": None}


def test_status_rend_mode_connu_et_wan_sans_bloquer_la_boucle(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "absent.json")
    monkeypatch.setattr(main, "_ifaces", lambda: [{"name": "eth2", "state": "up", "mac": "", "addrs": [], "type": "ether"}])
    monkeypatch.setattr(main, "_route_defaut", lambda: {"interface": "eth2", "passerelle": "192.0.2.1"})
    r = asyncio.run(main.status(user={}))
    assert r["mode_connu"] is False and r["current_mode"] is None and r["wan"] == {"interface": "eth2", "passerelle": "192.0.2.1"}
    assert main.status.__code__.co_flags & 0x80                                           # reste une coroutine, le travail bloquant part en thread
