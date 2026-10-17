# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Renouveler un certificat depuis le panneau (#2874).

L'API est servie par l'agregateur sous l'utilisateur secubox : certbot lancé
directement y échoue sur /var/log/letsencrypt/.certbot.lock. Le renouvellement
passe donc par `certsctl renew <domaine>` (root, via sudo), qui valide le nom,
lance certbot puis redéploie le pem.
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CTL = Path(__file__).resolve().parents[1] / "sbin" / "certsctl"


def _env(tmp_path, certbot_rc=0):
    certs = tmp_path / "certs"
    certs.mkdir(exist_ok=True)
    journal = tmp_path / "certbot.args"
    fake = tmp_path / "certbot"
    fake.write_text(f'#!/bin/sh\necho "$@" > {journal}\nexit {certbot_rc}\n')
    fake.chmod(0o755)
    return certs, journal, {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SECUBOX_CERTS_DIR": str(certs),
        "SECUBOX_ACME_HOME": str(tmp_path / "acme"),
        "SECUBOX_CERTBOT_LIVE": str(tmp_path / "live"),
        "SECUBOX_CERTBOT_BIN": str(fake),
        "SECUBOX_CERTS_RELOAD": "/bin/true",
    }


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args, capture_output=True,
                          text=True, env=env, timeout=60)


def test_renew_lance_certbot_avec_le_bon_nom(tmp_path):
    certs, journal, env = _env(tmp_path)
    (certs / "apt.example.com.pem").write_text("x")
    r = _run(["renew", "apt.example.com"], env)
    assert r.returncode == 0, r.stderr
    assert journal.read_text().split() == [
        "renew", "--cert-name", "apt.example.com", "--force-renewal",
        "--non-interactive"]
    assert json.loads(r.stdout.strip().splitlines()[-1])["success"] is True


@pytest.mark.parametrize("mauvais", [
    "../etc/passwd", "a b", "-x", "a;rm", "$(id)", "", "a/b", "a..b.", "*.x"])
def test_renew_refuse_un_nom_invalide(tmp_path, mauvais):
    certs, journal, env = _env(tmp_path)
    r = _run(["renew", mauvais], env)
    assert r.returncode == 2
    assert not journal.exists(), "certbot ne doit pas etre lance"


def test_renew_domaine_inconnu(tmp_path):
    certs, journal, env = _env(tmp_path)
    r = _run(["renew", "absent.example.com"], env)
    assert r.returncode == 3
    assert not journal.exists()


def test_renew_echec_certbot_remonte(tmp_path):
    certs, journal, env = _env(tmp_path, certbot_rc=1)
    (certs / "apt.example.com.pem").write_text("x")
    r = _run(["renew", "apt.example.com"], env)
    assert r.returncode == 1
    assert json.loads(r.stdout.strip().splitlines()[-1])["success"] is False


def test_api_passe_par_sudo_certsctl():
    import api.main as M
    ok = mock.Mock(returncode=0, stdout='{"success": true}\n', stderr="")
    with mock.patch.object(M.subprocess, "run", return_value=ok) as run, \
         mock.patch.object(Path, "exists", return_value=True):
        import asyncio
        out = asyncio.run(M.renew_certificate("apt.example.com"))
    cmd = run.call_args[0][0]
    assert cmd == ["sudo", "-n", "/usr/sbin/certsctl", "renew", "apt.example.com"]
    assert out["success"] is True


def test_api_remonte_l_echec():
    import api.main as M
    ko = mock.Mock(returncode=1, stdout='{"success": false}\n', stderr="boom")
    with mock.patch.object(M.subprocess, "run", return_value=ko), \
         mock.patch.object(Path, "exists", return_value=True):
        import asyncio
        out = asyncio.run(M.renew_certificate("apt.example.com"))
    assert out["success"] is False and "boom" in out["error"]


def test_postinst_pose_le_sudoers_exact():
    post = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    assert "secubox ALL=(root) NOPASSWD: /usr/sbin/certsctl renew *" in post
    assert "visudo -cf /etc/sudoers.d/secubox-certs" in post
