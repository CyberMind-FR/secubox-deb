# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 — interrupteur « Accès SSH » (API) et secubox-sshctl (garde du mot de passe par défaut)."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

SYSTEM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SYSTEM.parents[1] / "common"))

# Chargé par son chemin : le nom de paquet `api` est aussi celui des composants (ksm…) testés dans la même session.
_spec = importlib.util.spec_from_file_location("ssh_router_3401", SYSTEM / "api" / "routers" / "ssh.py")
ssh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ssh)

CTL = SYSTEM / "sbin" / "secubox-sshctl"


# ── API ────────────────────────────────────────────────────────────────
@pytest.fixture
def client(monkeypatch):
    appels = []

    def faux_ctl(args):
        appels.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"service": True}), stderr="")
    monkeypatch.setattr(ssh, "_ctl", faux_ctl)
    app = FastAPI()
    app.include_router(ssh.router)
    app.dependency_overrides[ssh.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    c.appels = appels
    return c


def test_routes_gardees_par_require_jwt():
    for r in ssh.router.routes:
        assert any(d.call is ssh.require_jwt for d in r.dependant.dependencies), r.path


def test_acces_passe_par_le_ctl_avec_l_acteur(client):
    assert client.post("/ssh/acces", json={"actif": True}).status_code == 200
    assert client.appels[-1] == ["acces", "on", "admin"]


def test_mot_de_passe_refuse_tant_que_le_defaut_est_actif(client, monkeypatch):
    monkeypatch.setattr(ssh.mdp_defaut, "actif", lambda *a, **k: True)
    monkeypatch.setattr(ssh.mdp_defaut, "audit", lambda *a, **k: None)
    r = client.post("/ssh/mot-de-passe", json={"actif": True})
    assert r.status_code == 409 and "mot de passe par défaut" in r.json()["detail"]
    assert client.appels == []


def test_refuser_le_mot_de_passe_reste_possible_avec_le_defaut(client, monkeypatch):
    monkeypatch.setattr(ssh.mdp_defaut, "actif", lambda *a, **k: True)
    assert client.post("/ssh/mot-de-passe", json={"actif": False}).status_code == 200
    assert client.appels[-1] == ["mot-de-passe", "off", "admin"]


def test_mot_de_passe_permis_apres_changement(client, monkeypatch):
    monkeypatch.setattr(ssh.mdp_defaut, "actif", lambda *a, **k: False)
    assert client.post("/ssh/mot-de-passe", json={"actif": True}).status_code == 200


# ── ctl ────────────────────────────────────────────────────────────────
def _ctl(tmp_path, *args, defaut="1"):
    env = {**os.environ, "SECUBOX_SSHD_DIR": str(tmp_path), "SECUBOX_AUDIT_LOG": str(tmp_path / "audit.log"),
           "SECUBOX_SSHCTL_ESSAI": "1", "SECUBOX_DEFAUT_ACTIF": defaut}
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=30, check=False)


def test_garde_posee_puis_levee_et_auditee(tmp_path):
    garde = tmp_path / "05-secubox-mot-de-passe-defaut.conf"
    assert _ctl(tmp_path, "garde", defaut="1").returncode == 0
    assert "PasswordAuthentication no" in garde.read_text()
    assert _ctl(tmp_path, "garde", defaut="0").returncode == 0
    assert not garde.exists()
    ev = [json.loads(x)["evenement"] for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert ev == ["ssh_garde_defaut_posee", "ssh_garde_defaut_levee"]


def test_ctl_refuse_le_mot_de_passe_avec_le_defaut(tmp_path):
    r = _ctl(tmp_path, "mot-de-passe", "on", "admin", defaut="1")
    assert r.returncode == 3 and "mot de passe par défaut" in r.stderr


def test_ctl_mot_de_passe_off_puis_on(tmp_path):
    f = tmp_path / "10-secubox-ssh-mot-de-passe.conf"
    assert _ctl(tmp_path, "mot-de-passe", "off", "admin", defaut="0").returncode == 0
    assert "PasswordAuthentication no" in f.read_text()
    assert _ctl(tmp_path, "mot-de-passe", "on", "admin", defaut="0").returncode == 0
    assert not f.exists()


def test_ctl_etat(tmp_path):
    _ctl(tmp_path, "garde", defaut="1")
    e = json.loads(_ctl(tmp_path, "etat", defaut="1").stdout)
    assert e["garde_defaut"] and not e["mot_de_passe"] and e["mot_de_passe_defaut"]


@pytest.mark.parametrize("args", [["acces", "peut-etre", "admin"], ["acces", "on", "a b"], ["rm"], []])
def test_ctl_refuse_les_arguments_hors_liste(tmp_path, args):
    assert _ctl(tmp_path, *args).returncode == 2
