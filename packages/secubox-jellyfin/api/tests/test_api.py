# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""API native LXC de jellyfin (#1771) — restaurée après la fusion aff481735.

La garde la plus utile ici : CHAQUE route que la page appelle existe dans
l'API. C'est exactement ce que la fusion avait cassé sans qu'aucun test ne
proteste (la page appelait /partners, /control… et recevait 404).
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAQUET.parents[1] / "common"))
sys.path.insert(0, str(PAQUET))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as M  # noqa: E402

PAGE = (PAQUET / "www" / "jellyfin" / "index.html").read_text()


def test_chaque_route_de_la_page_existe():
    appelees = set(re.findall(r'api(?:Get|Post)\(\s*"(/[a-z/-]+)"', PAGE))
    assert appelees, "aucun appel trouvé : le motif de la page a changé ?"
    servies = {r.path for r in M.app.routes}
    assert appelees <= servies, sorted(appelees - servies)


def test_aucun_docker_dans_le_code_execute():
    import ast
    arbre = ast.parse((PAQUET / "api" / "main.py").read_text())
    docs = {id(n.body[0].value) for n in ast.walk(arbre)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    for n in ast.walk(arbre):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
            assert not re.search(r"\b(docker|podman)\b", n.value.lower()), n.value


@pytest.fixture
def client(monkeypatch):
    M.app.dependency_overrides[M.require_jwt] = lambda: {"sub": "admin"}
    M.app.dependency_overrides[M.require_lecture] = lambda: {"sub": "admin"}
    appels = []

    def faux(cmd, **k):
        appels.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"success": True}), stderr="")
    monkeypatch.setattr(M.subprocess, "run", faux)
    yield TestClient(M.app), appels
    M.app.dependency_overrides.clear()


def test_actions_par_sudo_jellyfinctl(client):
    c, appels = client
    assert c.post("/control", json={"action": "restart"}).json() == {"success": True}
    assert c.post("/partner/wire", json={"all": True}).status_code == 200
    assert appels == [["sudo", "-n", M.CTL, "restart"],
                      ["sudo", "-n", M.CTL, "partner", "wire", "--all"]]


def test_action_refusee_avant_le_helper(client):
    c, appels = client
    assert c.post("/control", json={"action": "rm"}).status_code == 400
    assert appels == []


def test_action_longue_rend_la_main(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(M, "DELAI_REPONSE", 0.2)

    def lent(cmd, **k):
        time.sleep(1.0)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"success": true}', stderr="")
    monkeypatch.setattr(M.subprocess, "run", lent)
    assert c.post("/upgrade").json()["pending"] is True
