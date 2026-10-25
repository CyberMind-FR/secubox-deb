# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API hôte dédiée de secubox-meet (#3154) : tout passe par `sudo -n meetctl`."""
import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException, Request

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE.parents[1] / "common"))
sys.path.insert(0, str(RACINE))

import api.main as M  # noqa: E402


def _jwt(req: Request):
    if req.headers.get("x-test-jwt") != "1":
        raise HTTPException(status_code=401, detail="non authentifié")
    return {"sub": "admin"}


def _lecture(req: Request):
    if req.headers.get("x-test-lecture") != "1":
        raise HTTPException(status_code=401, detail="non authentifié")
    return {"sub": "admin"}


class Client:
    def __init__(self):
        self.appels = []
        self.sorties = {}

    def _req(self, methode, chemin, jwt, lecture, **kw):
        en_tetes = {}
        if jwt:
            en_tetes["x-test-jwt"] = "1"
        if lecture:
            en_tetes["x-test-lecture"] = "1"

        async def go():
            transport = httpx.ASGITransport(app=M.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                return await c.request(methode, chemin, headers=en_tetes, **kw)
        return asyncio.run(go())

    def get(self, chemin, jwt=False, lecture=True):
        return self._req("GET", chemin, jwt, lecture)

    def post(self, chemin, json=None, jwt=False):
        return self._req("POST", chemin, jwt, False, json=json)


@pytest.fixture
def cli(monkeypatch, tmp_path):
    c = Client()
    monkeypatch.setattr(M, "STATUS_CACHE_FILE", tmp_path / "status.json")
    monkeypatch.setattr(M, "CACHE_DIR", tmp_path)
    M._status_cache.update(data=None, ts=0.0)
    M.app.dependency_overrides[M.require_jwt] = _jwt
    M.app.dependency_overrides[M.require_lecture] = _lecture

    def faux(*args, timeout=30):
        c.appels.append(tuple(args))
        return 0, c.sorties.get(args[0], json.dumps({"success": True})), ""
    monkeypatch.setattr(M, "_run_ctl", faux)
    yield c
    M.app.dependency_overrides.clear()


def test_health_libre(cli):
    r = cli.get("/health", lecture=False)
    assert r.status_code == 200 and r.json() == {"status": "ok", "module": "meet"}


def test_media_expose_exige_jwt_et_confirmation(cli):
    assert cli.post("/media-expose", json={"action": "apply"}, jwt=False).status_code == 401
    r = cli.post("/media-expose", json={"action": "apply"}, jwt=True)
    assert r.status_code == 400 and 'confirmer: "meet"' in r.json()["detail"]
    assert cli.post("/media-expose", json={"action": "apply", "confirmer": "autre"}, jwt=True).status_code == 400
    assert not cli.appels
    assert cli.post("/media-expose", json={"action": "apply", "confirmer": "meet"}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("media-expose", "--apply")
    assert cli.post("/media-expose", json={"action": "revoke", "confirmer": "meet"}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("media-expose", "--revoke")


def test_media_expose_action_inconnue_400(cli):
    r = cli.post("/media-expose", json={"action": "detruire", "confirmer": "meet"}, jwt=True)
    assert r.status_code == 400 and not cli.appels


def test_media_expose_lecture(cli):
    assert cli.get("/media-expose", lecture=False).status_code == 401
    assert cli.get("/media-expose").status_code == 200
    assert cli.appels == [("media-expose",)]


def test_control_refuse_une_action_inconnue(cli):
    assert cli.post("/control", json={"action": "destroy"}, jwt=True).status_code == 400 and not cli.appels


def test_control_exige_jwt_et_delegue(cli):
    assert cli.post("/control", json={"action": "restart"}, jwt=False).status_code == 401
    assert cli.post("/control", json={"action": "restart"}, jwt=True).status_code == 200
    assert cli.appels == [("restart",)]


def test_status_lecture_cachee(cli):
    cli.get("/status"); cli.get("/status")
    assert cli.appels.count(("status",)) == 1


def test_status_exige_lecture(cli):
    assert cli.get("/status", lecture=False).status_code == 401 and not cli.appels


def test_status_ecrit_le_cache_fichier(cli):
    cli.get("/status")
    assert json.loads(M.STATUS_CACHE_FILE.read_text()) == {"success": True}


def test_logs_unite_inconnue_400(cli):
    assert cli.get("/logs?unit=sshd", jwt=True).status_code == 400


def test_logs_exige_jwt_et_borne_les_lignes(cli):
    assert cli.get("/logs?unit=livekit", lecture=False).status_code == 401
    cli.sorties["logs"] = "a\nb\n"
    r = cli.get("/logs?unit=livekit&lines=99999", jwt=True)
    assert r.status_code == 200 and r.json() == {"unit": "livekit", "lines": ["a", "b"]}
    assert cli.appels[-1] == ("logs", "livekit", "500")
    cli.get("/logs?unit=nginx&lines=-4", jwt=True)
    assert cli.appels[-1] == ("logs", "nginx", "1")


def test_oidc_verifier_et_enregistrer_exigent_jwt(cli):
    assert cli.get("/oidc", lecture=False).status_code == 401
    assert cli.post("/oidc/enregistrer", json={}, jwt=False).status_code == 401
    assert not cli.appels
    assert cli.get("/oidc", jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-verifier",)
    assert cli.post("/oidc/enregistrer", json={}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-enregistrer",)
    assert cli.post("/oidc/enregistrer", json={"renouveler": True}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-enregistrer", "--renouveler")


def test_erreur_du_ctl_remonte_en_500(cli, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, "", "boom"))
    r = cli.post("/control", json={"action": "start"}, jwt=True)
    assert r.status_code == 500 and "boom" in r.json()["detail"]


def test_import_strict_de_l_authentification():
    src = (RACINE / "api" / "main.py").read_text()
    assert "except ImportError" not in src and "from secubox_core.auth import require_jwt, require_lecture" in src
