# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1756 — ce que la fusion aff481735 avait effacé (09e1884fb, 2632596b6).

Un mot de passe ne passe JAMAIS par argv ni par une chaîne de shell : il va
sur l'entrée standard de `nextcloudctl user setpass`. Les uid et noms de
sauvegarde sont validés avant d'atteindre le helper root, et les verbes qui
demandent « yes » le reçoivent au lieu d'abandonner sur EOF.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

HOSTILE = "a'; touch /tmp/pwn; echo '$(id)`id`"


def _load(monkeypatch, running=True):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "lxc_running", lambda: running)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    appels = []

    def faux_run_cmd(cmd, timeout=30, stdin=None):
        appels.append({"cmd": list(cmd), "stdin": stdin})
        return True, "", ""
    monkeypatch.setattr(m, "run_cmd", faux_run_cmd)
    return m, TestClient(m.app), appels


def test_mot_de_passe_par_stdin_jamais_argv(monkeypatch):
    m, c, appels = _load(monkeypatch)
    r = c.post("/user/password", json={"uid": "alice", "password": HOSTILE})
    assert r.status_code == 200, r.text
    (appel,) = appels
    assert appel["cmd"][-3:] == ["user", "setpass", "alice"]
    assert not any(HOSTILE in a or "OC_PASS" in a for a in appel["cmd"])
    assert appel["stdin"] == HOSTILE + "\n"


@pytest.mark.parametrize("uid", ["alice'; id", "a b", "", "alice\n", "../x"])
def test_uid_hostile_refuse(monkeypatch, uid):
    m, c, appels = _load(monkeypatch)
    r = c.post("/user/password", json={"uid": uid, "password": "x"})
    assert r.status_code == 400 and appels == []


@pytest.mark.parametrize("pwd", ["", "deux\nlignes", "a\rb", "nul\0"])
def test_mot_de_passe_multiligne_refuse(monkeypatch, pwd):
    m, c, appels = _load(monkeypatch)
    r = c.post("/user/password", json={"uid": "alice", "password": pwd})
    assert r.status_code == 400 and appels == []


def test_conteneur_arrete_409(monkeypatch):
    m, c, appels = _load(monkeypatch, running=False)
    assert c.post("/user/password", json={"uid": "alice", "password": "x"}).status_code == 409
    assert appels == []


@pytest.mark.parametrize("nom", ["x;id", "a b", "../../etc", "x\n"])
def test_nom_de_sauvegarde_hostile_refuse(monkeypatch, nom):
    m, c, appels = _load(monkeypatch)
    assert c.post("/backup", json={"name": nom}).status_code == 400
    assert appels == []


def test_desinstallation_confirme(monkeypatch):
    m, c, appels = _load(monkeypatch)
    assert c.post("/uninstall").status_code == 200
    assert appels[0]["cmd"][-1] == "uninstall" and appels[0]["stdin"] == "yes\n"
