# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""API native LXC de jitsi (#1761) — restaurée après la fusion aff481735.

Tout passe par `sudo -n jitsictl` ; aucun docker/podman ; pas de repli
d'authentification ; /status sert un cache à durée de vie (pas de crochet de
démarrage sous l'agrégateur) ; une action longue rend la main avant les 30 s
d'HAProxy.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as M  # noqa: E402

SOURCE = (Path(__file__).resolve().parents[1] / "main.py").read_text()


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(M, "STATUS_CACHE_FILE", tmp_path / "status.json")
    monkeypatch.setattr(M, "CACHE_DIR", tmp_path)
    M._status_cache.update(data=None, ts=0.0)
    M.app.dependency_overrides[M.require_jwt] = lambda: {"sub": "admin"}
    M.app.dependency_overrides[M.require_lecture] = lambda: {"sub": "admin"}
    appels = []

    def faux(cmd, **k):
        appels.append(cmd)
        sortie = {"status": {"installed": True, "container": "running"},
                  "stats": {"conferences": 2, "participants": 5}}.get(cmd[3], {"success": True})
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(sortie), stderr="")
    monkeypatch.setattr(M.subprocess, "run", faux)
    yield TestClient(M.app), appels
    M.app.dependency_overrides.clear()


def test_aucun_docker_ni_repli_d_authentification():
    """Sur le code EXÉCUTÉ (AST), pas sur les docstrings qui racontent
    l'ancienne version : aucune chaîne docker/podman/compose, aucun
    `except ImportError` (le repli rendait {"sub": "admin"})."""
    import ast
    arbre = ast.parse(SOURCE)
    docs = set()
    for n in ast.walk(arbre):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant):
                docs.add(id(n.body[0].value))
    for n in ast.walk(arbre):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
            for interdit in ("docker", "podman", "compose"):
                assert interdit not in n.value.lower(), n.value
        if isinstance(n, ast.ExceptHandler):
            assert not (isinstance(n.type, ast.Name) and n.type.id == "ImportError")


def test_tout_passe_par_sudo_jitsictl(client):
    c, appels = client
    assert c.post("/control", json={"action": "restart"}).json() == {"success": True}
    assert c.post("/service/restart", json={"unit": "jicofo"}).status_code == 200
    assert appels == [["sudo", "-n", M.CTL, "restart"],
                      ["sudo", "-n", M.CTL, "service-restart", "jicofo"]]


@pytest.mark.parametrize("corps,route", [({"action": "rm -rf"}, "/control"),
                                         ({"unit": "sshd"}, "/service/restart"),
                                         ({"address": "  "}, "/public-ip")])
def test_valeurs_refusees_avant_le_helper(client, corps, route):
    c, appels = client
    assert c.post(route, json=corps).status_code == 400
    assert appels == []


def test_status_cache_a_duree_de_vie(client, monkeypatch):
    c, appels = client
    assert c.get("/status").json()["container"] == "running"
    c.get("/status")
    assert len(appels) == 1                      # servi par le cache
    M._status_cache["ts"] = time.time() - M.STATUS_TTL - 1
    (M.STATUS_CACHE_FILE).write_text("{}")
    import os
    ancien = time.time() - M.STATUS_TTL - 5
    os.utime(M.STATUS_CACHE_FILE, (ancien, ancien))
    c.get("/status")
    assert len(appels) == 2                      # périmé : rafraîchi


def test_status_garde_la_derniere_valeur_si_jitsictl_echoue(client, monkeypatch):
    c, appels = client
    c.get("/status")
    M._status_cache["ts"] = 0.0
    import os
    os.utime(M.STATUS_CACHE_FILE, (0, 0))
    monkeypatch.setattr(M.subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="panne"))
    assert c.get("/status").json()["container"] == "running"


def test_action_longue_rend_la_main(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(M, "DELAI_REPONSE", 0.2)

    def lent(cmd, **k):
        time.sleep(1.0)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"success": true}', stderr="")
    monkeypatch.setattr(M.subprocess, "run", lent)
    assert c.post("/control", json={"action": "stop"}).json()["pending"] is True
