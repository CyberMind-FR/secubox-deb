# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3494 : détail par appareil tiré du moteur vivant ; un cumul figé ne passe plus pour de l'activité."""
import json
import time

from api import main as M


def test_clients_regroupes_par_appareil(monkeypatch):
    monkeypatch.setattr(M, "_client_name", lambda d, dev: "nom-" + d)
    r = M._clients_depuis_sessions([
        {"device": "a", "usage": "web", "infra": "Fastly", "start": 10, "last": 20, "flows": 2, "bytes": 100},
        {"device": "a", "usage": "video", "application": "YouTube", "infra": "Google", "start": 5, "last": 30, "flows": 3, "bytes": 300},
        {"device": "b", "usage": "web", "start": 1, "last": 2, "flows": 1, "bytes": 1},
    ])
    assert [c["device"] for c in r] == ["a", "b"]
    a = r[0]
    assert (a["name"], a["bytes"], a["flows"], a["first_seen"], a["last_seen"]) == ("nom-a", 400, 5, 5, 30)
    assert a["top_dst"][0] == {"host": "YouTube", "bytes": 300, "service": ""}
    assert a["usages"][0]["name"] == "video"
    assert "up_bytes" not in a and "down_bytes" not in a


def test_cumul_fige_ecarte(tmp_path, monkeypatch):
    f = tmp_path / "c.json"
    n = time.time()
    f.write_text(json.dumps({"devices": [{"device": "vieux", "last_seen": n - 23 * 86400}, {"device": "recent", "last_seen": n - 60}]}))
    monkeypatch.setattr(M, "COLLECTOR_CUMUL", f)
    assert [d["device"] for d in M._collector_devices()] == ["recent"]
