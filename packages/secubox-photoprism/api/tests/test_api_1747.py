# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""API photoprism : routes reprises (#1747).

- /config et /faces/* ne réécrivent plus /etc/secubox/photoprism.toml à plat
  (les sections [lxc]/[photoprism]/[exposure] disparaissaient) ;
- /restore (archive désignée par un chemin libre du client) est retiré ;
- /backup passe par le verbe root `photoprismctl backup`, destination fixe ;
- stats et stockage viennent d'un cache (rglob / du par requête).
"""
import re
import sys
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAQUET.parents[1] / "common"))
sys.path.insert(0, str(PAQUET))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as M  # noqa: E402

PAGE = (PAQUET / "www" / "photoprism" / "index.html").read_text()
TOML = """[lxc]
name = "photoprism"
ip = "10.100.0.130"
[photoprism]
http_port = 2342
admin_password_file = "/etc/secubox/secrets/photoprism-admin"
[exposure]
public_hostname = "photoprism.gk2.secubox.in"
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    conf = tmp_path / "photoprism.toml"
    conf.write_text(TOML)
    monkeypatch.setattr(M, "CONFIG_FILE", conf)
    M.app.dependency_overrides[M.require_jwt] = lambda: {"sub": "admin"}
    getattr(M, "_mesures", {}).clear()
    yield TestClient(M.app), conf
    M.app.dependency_overrides.clear()


def test_chaque_route_de_la_page_existe():
    appelees = set(re.findall(r"api\('(/[a-z/_-]+)", PAGE)) | {"/faces/enable", "/faces/disable"}
    # Le schéma OpenAPI, pas app.routes : selon la version de FastAPI, un
    # routeur inclus y reste un objet opaque (_IncludedRouter).
    servies = set(M.app.openapi()["paths"])
    assert appelees <= servies, sorted(appelees - servies)


@pytest.mark.parametrize("route", ["/config", "/faces/enable", "/faces/disable"])
def test_reglages_ne_reecrivent_plus_le_fichier(client, route):
    c, conf = client
    r = c.post(route, json={"port": 9999, "data_path": "/srv/photoprism"})
    assert r.status_code == 200
    assert r.json()["success"] is False
    assert conf.read_text() == TOML, "la configuration a été réécrite"


def test_restore_est_retire(client):
    c, _ = client
    assert c.post("/restore", json={"path": "/etc/shadow"}).status_code in (404, 405)
    assert not hasattr(M, "RestoreRequest")


def test_backup_passe_par_le_verbe_root_detache(client, monkeypatch):
    c, _ = client
    lances = []

    class _Popen:
        def __init__(self, argv, **kw):
            lances.append(argv)
    monkeypatch.setattr(M.subprocess, "Popen", _Popen)
    monkeypatch.setattr(M, "open", lambda *a, **k: open("/dev/null", "a"), raising=False)
    r = c.post("/backup").json()
    assert r["success"] is True
    assert lances == [["sudo", "-n", M.PHOTOPRISMCTL, "backup"]]
    assert "/tmp" not in r["path"]


def test_statistiques_servies_depuis_le_cache(client, monkeypatch):
    c, _ = client
    appels = []
    monkeypatch.setattr(M, "get_library_stats", lambda: appels.append(1) or {"total_photos": 3})
    assert c.get("/library/stats").json()["total_photos"] == 3
    assert c.get("/library/stats").json()["total_photos"] == 3
    assert len(appels) == 1


def test_sudoers_admet_backup_sans_argument():
    s = (PAQUET / "debian" / "secubox-photoprism.sudoers").read_text()
    assert "/usr/sbin/photoprismctl backup" in s
    assert "*" not in s.split("NOPASSWD:", 1)[1], "joker dans la règle sudoers"


def test_ctl_backup_a_une_destination_fixe():
    ctl = (PAQUET / "sbin" / "photoprismctl").read_text()
    assert 'SAUVEGARDES="${PHOTOPRISM_SAUVEGARDES:-/var/backups/secubox/photoprism}"' in ctl
    assert "sqlite3" in ctl and ".backup" in ctl
