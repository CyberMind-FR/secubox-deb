# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3012 — supprimer un certificat passe par le contrôleur confiné, pas par l'API.

`delete_certificate` faisait lui-même `mkdir` + `rename` dans /srv/haproxy/certs (root 0755) alors que
l'API tourne en `secubox` : PermissionError, HTTP 500, « Suppression impossible ». Désormais l'API
appelle `sudo -n haproxyctl cert delete <nom>` (sudoers à argv exact livré par le postinst) et le
contrôleur met le .pem de côté dans certs/backup/.
"""
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main as api_main

PKG = Path(__file__).resolve().parents[1]
CTL = PKG / "sbin" / "haproxyctl"


def _ctl(tmp_path, *args):
    env = dict(os.environ, HAPROXY_DATA_PATH=str(tmp_path), SECUBOX_HAPROXY_CONFIG_DIR=str(tmp_path / "etc"),
               HAPROXYCTL_LOG=str(tmp_path / "ctl.log"))
    return subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, timeout=30, env=env, check=False)


def test_le_controleur_met_le_certificat_de_cote(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "anibal-amiot.com.pem").write_text("PEM")
    r = _ctl(tmp_path, "cert", "delete", "anibal-amiot.com")
    assert r.returncode == 0, r.stderr + r.stdout
    assert not (certs / "anibal-amiot.com.pem").exists()
    copies = list((certs / "backup").glob("anibal-amiot.com.pem.*"))
    assert len(copies) == 1 and copies[0].read_text() == "PEM"
    assert "anibal-amiot.com" in r.stdout


def test_le_controleur_refuse_un_nom_douteux_et_un_certificat_absent(tmp_path):
    (tmp_path / "certs").mkdir()
    for nom in ("../etc", "a/b", "", "*.gk2.secubox.in; rm"):
        r = _ctl(tmp_path, "cert", "delete", nom)
        assert r.returncode != 0, nom
    r = _ctl(tmp_path, "cert", "delete", "absent.example")
    assert r.returncode == 2 and "absent" in (r.stderr + r.stdout)


@pytest.fixture
def client(monkeypatch):
    from secubox_core.auth import require_jwt
    api_main.app.dependency_overrides[require_jwt] = lambda: None
    yield TestClient(api_main.app)
    api_main.app.dependency_overrides.clear()


def test_l_api_delegue_au_controleur_sous_sudo(client, tmp_path, monkeypatch):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "anibal-amiot.fr.pem").write_text("PEM")
    monkeypatch.setattr(api_main, "CERTS_DIR", str(certs))
    appels = []

    def faux_run(args, **kw):
        appels.append(list(args))
        return subprocess.CompletedProcess(args, 0, "mis de cote : %s/backup/anibal-amiot.fr.pem.20261022_050000\n" % certs, "")
    monkeypatch.setattr(api_main.subprocess, "run", faux_run)
    r = client.delete("/certificates/anibal-amiot.fr")
    assert r.status_code == 200, r.text
    assert appels == [["sudo", "-n", "/usr/sbin/haproxyctl", "cert", "delete", "anibal-amiot.fr"]]
    assert r.json()["success"] is True and "backup" in r.json()


def test_l_api_rend_une_erreur_claire_quand_le_controleur_echoue(client, tmp_path, monkeypatch):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "x.pem").write_text("PEM")
    monkeypatch.setattr(api_main, "CERTS_DIR", str(certs))
    monkeypatch.setattr(api_main.subprocess, "run",
                        lambda args, **kw: subprocess.CompletedProcess(args, 1, "", "sudo: a password is required"))
    r = client.delete("/certificates/x")
    assert r.status_code == 502 and "password" in r.json()["detail"]


def test_l_api_refuse_un_nom_douteux_avant_tout_appel(client, tmp_path, monkeypatch):
    monkeypatch.setattr(api_main, "CERTS_DIR", str(tmp_path))
    appels = []
    monkeypatch.setattr(api_main.subprocess, "run", lambda args, **kw: appels.append(args))
    assert client.delete("/certificates/..%2Fetc").status_code in (400, 404)
    assert client.delete("/certificates/a%3Bb").status_code == 400
    assert appels == []


def test_le_postinst_livre_le_sudoers_a_argv_exact():
    postinst = (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert "secubox ALL=(root) NOPASSWD: /usr/sbin/haproxyctl cert delete *" in postinst
    assert "visudo -cf /etc/sudoers.d/secubox-haproxy" in postinst
