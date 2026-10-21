# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3000 — routes /smb/* : toutes sous jeton, délégation à `sudo -n smbctl`, mot de passe sur stdin, refus = 400 motivé."""
import json
import re
import subprocess
from pathlib import Path

import pytest

SRC = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")


def test_toutes_les_routes_smb_exigent_un_jeton():
    routes = re.findall(r'@app\.(get|post)\("(/smb/[^"]*)"[^\n]*\)\nasync def (\w+)\(([^)]*)\)', SRC)
    assert {r[1] for r in routes} == {"/smb/status", "/smb/users", "/smb/users/delete", "/smb/shares",
                                      "/smb/shares/delete", "/smb/sync-shares", "/smb/reload"}
    for verbe, route, fn, params in routes:
        decor = SRC[SRC.rfind("@app.", 0, SRC.index(f"async def {fn}(")):SRC.index(f"async def {fn}(")]
        assert "require_jwt" in decor + params, route
        assert "require_lecture" not in decor + params and "require_session" not in decor + params, route


def test_le_mot_de_passe_ne_passe_jamais_en_argument():
    corps = SRC[SRC.index("async def smb_user_add"):SRC.index("async def smb_user_del")]
    assert "stdin=body.password" in corps
    assert re.search(r'_smb\("user-add", body\.user, stdin=', corps)
    assert "body.password," not in corps and "body.password)" not in corps


pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest.fixture
def client(monkeypatch):
    try:
        import api.main as m
    except ImportError as e:  # secubox_core hors environnement
        pytest.skip(str(e))
    from fastapi.testclient import TestClient
    appels = []

    def faux_run(cmd, input=None, capture_output=True, text=True, timeout=30):
        appels.append((cmd, input))
        sortie = {"ok": True}
        if cmd[3] == "share-add" and cmd[4] == "Refuse":
            sortie = {"ok": False, "error": "chemin hors des racines partageables"}
        if cmd[3] == "status":
            sortie = {"ok": True, "usable": True, "shares": [], "users": 1, "netbios": "SECUBOX"}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(sortie) + "\n", "")

    monkeypatch.setattr(m.subprocess, "run", faux_run)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(m.app), appels
    m.app.dependency_overrides.clear()


def test_user_add_delegue_a_sudo_smbctl_avec_le_secret_sur_stdin(client):
    c, appels = client
    r = c.post("/smb/users", json={"user": "gk2", "password": "s3cret"})
    assert r.status_code == 200 and r.json()["ok"]
    cmd, entree = appels[-1]
    assert cmd[:4] == ["sudo", "-n", "/usr/sbin/smbctl", "user-add"] and cmd[4] == "gk2" and len(cmd) == 5
    assert entree == "s3cret\n" and "s3cret" not in " ".join(cmd)


def test_share_add_transmet_les_options_en_liste(client):
    c, appels = client
    r = c.post("/smb/shares", json={"name": "Photos", "path": "/data/photos", "readonly": False, "users": ["gk2", " admin "], "comment": "Albums"})
    assert r.status_code == 200
    cmd, _ = appels[-1]
    assert cmd[3:] == ["share-add", "Photos", "/data/photos", "--rw", "--users", "gk2,admin", "--comment", "Albums"]
    r = c.post("/smb/shares", json={"name": "Lect", "path": "/data/x"})
    assert appels[-1][0][3:] == ["share-add", "Lect", "/data/x", "--ro"]      # lecture seule par défaut


def test_un_refus_du_ctl_devient_un_400_motive(client):
    c, _ = client
    r = c.post("/smb/shares", json={"name": "Refuse", "path": "/etc"})
    assert r.status_code == 400 and "hors des racines" in r.json()["detail"]


def test_status_sync_reload_et_suppressions(client):
    c, appels = client
    assert c.get("/smb/status").json()["netbios"] == "SECUBOX"
    assert c.post("/smb/sync-shares").status_code == 200 and appels[-1][0][3] == "sync-shares"
    assert c.post("/smb/reload").status_code == 200 and appels[-1][0][3] == "reload"
    assert c.post("/smb/shares/delete", json={"name": "P"}).status_code == 200 and appels[-1][0][3:] == ["share-del", "P"]
    assert c.post("/smb/users/delete", json={"user": "u"}).status_code == 200 and appels[-1][0][3:] == ["user-del", "u"]
