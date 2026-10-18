# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2901 — Activer KSM : HTTP 500 parce que l'API, servie par l'agregateur sous secubox, ecrivait sysfs (root).
Le module passe par secubox-ksmctl (root, via sudo) ; le ctl valide tout."""
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

ICI = Path(__file__).resolve().parents[1]
CTL = ICI / "sbin" / "secubox-ksmctl"
sys.path.insert(0, str(ICI.parents[1] / "common"))
sys.path.insert(0, str(ICI / "composants" / "ksm"))


def _sys(tmp_path):
    d = tmp_path / "ksm"
    d.mkdir()
    for n, v in (("run", "0"), ("pages_to_scan", "100"), ("sleep_millisecs", "20")):
        (d / n).write_text(v + "\n")
    return d


def _ctl(tmp_path, *args):
    env = {"PATH": os.environ["PATH"], "SECUBOX_KSM_SYSFS": str(_sys(tmp_path) if not (tmp_path / "ksm").exists() else tmp_path / "ksm")}
    return subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, env=env, timeout=20)


def test_run_ecrit_0_ou_1(tmp_path):
    assert _ctl(tmp_path, "run", "1").returncode == 0
    assert (tmp_path / "ksm" / "run").read_text().strip() == "1"
    assert _ctl(tmp_path, "run", "0").returncode == 0
    assert (tmp_path / "ksm" / "run").read_text().strip() == "0"


@pytest.mark.parametrize("v", ["2", "-1", "a", "1;x", "", "1 2"])
def test_run_refuse_une_valeur_invalide(tmp_path, v):
    r = _ctl(tmp_path, "run", v)
    assert r.returncode == 2
    assert (tmp_path / "ksm" / "run").read_text().strip() == "0"


def test_config_valide_les_bornes(tmp_path):
    assert _ctl(tmp_path, "config", "200", "50").returncode == 0
    assert (tmp_path / "ksm" / "pages_to_scan").read_text().strip() == "200"
    assert (tmp_path / "ksm" / "sleep_millisecs").read_text().strip() == "50"
    for args in (("0", "50"), ("20000", "50"), ("100", "5"), ("100", "5000"), ("x", "50")):
        assert _ctl(tmp_path, "config", *args).returncode == 2


def test_verbe_inconnu_refuse(tmp_path):
    assert _ctl(tmp_path, "rm", "-rf").returncode == 2


@pytest.fixture
def ksm():
    from secubox_core import auth  # noqa: F401
    import api.main as M
    return M


def test_l_api_passe_par_sudo_ksmctl(ksm):
    import asyncio
    ok = mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch.object(ksm, "_ksm_available", return_value=True), \
         mock.patch.object(ksm.subprocess, "run", return_value=ok) as run:
        out = asyncio.run(ksm.enable_ksm({"sub": "admin"}))
    assert run.call_args[0][0] == ["sudo", "-n", "/usr/sbin/secubox-ksmctl", "run", "1"]
    assert out["success"] is True


def test_l_api_remonte_l_echec_du_ctl(ksm):
    import asyncio
    from fastapi import HTTPException
    ko = mock.Mock(returncode=1, stdout="", stderr="boom")
    with mock.patch.object(ksm, "_ksm_available", return_value=True), \
         mock.patch.object(ksm.subprocess, "run", return_value=ko):
        with pytest.raises(HTTPException) as e:
            asyncio.run(ksm.disable_ksm({"sub": "admin"}))
    assert e.value.status_code == 500


def test_postinst_sudoers_exact_et_pas_de_rallumage():
    post = (ICI / "composants/ksm/debian/postinst").read_text()
    assert "secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-ksmctl run *, /usr/sbin/secubox-ksmctl config *" in post
    assert "visudo -cf /etc/sudoers.d/secubox-ksm" in post
    assert '[ -z "${2:-}" ]' in post, "enable/start seulement a la premiere installation"
