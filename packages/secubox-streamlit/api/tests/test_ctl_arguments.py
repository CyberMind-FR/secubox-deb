# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""streamlitctl valide lui-même ses arguments (défense en profondeur).

L'API refuse les noms malformés avant `sudo`, mais la règle sudoers admet tout
argument : un processus du compte `secubox` peut appeler le script en root
sans passer par l'API. Ces tests appellent donc le VRAI script, directement,
avec ce qu'un tel appelant pourrait lui passer.
"""

import os
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"
REFUS = 64


def _env(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    return dict(
        os.environ,
        SECUBOX_STREAMLIT_APPS_PATH=str(apps),
        SECUBOX_STREAMLIT_CONF=str(tmp_path / "streamlit.toml"),
        SECUBOX_STREAMLIT_IDLE_DIR=str(tmp_path / "idle"),
    )


def _ctl(env, *args):
    return subprocess.run(["bash", str(CTL), *args], env=env,
                          capture_output=True, text=True, timeout=30)


def test_remove_ne_sort_pas_du_depot_d_applis(tmp_path):
    env = _env(tmp_path)
    victime = tmp_path / "victime"
    victime.mkdir()
    (victime / "garde").write_text("x")

    r = _ctl(env, "app", "remove", "../victime")

    assert r.returncode == REFUS, r.stderr
    assert (victime / "garde").exists(), "rm -rf est sorti du dépôt d'applis"


@pytest.mark.parametrize("args", [
    ("app", "remove", "../victime"),
    ("app", "stop", "a/b"),
    ("app", "info", ".cache"),
    ("app", "archive", "-x"),
    ("app", "start", "ok", "80;id"),
    ("app", "wake", "ok", "15 20"),
    ("app", "logs", "ok", "$(id)"),
    ("app", "wake-by-port", "8501x"),
    ("app", "deploy", "/tmp/x.zip", "../x"),
    ("instance", "start", "../x"),
    ("gitea", "push", "a b"),
    ("gitea", "clone", "ok", "--upload-pack=touch /tmp/sbx-pwn"),
    ("gitea", "clone", "ok", "file:///etc"),
    ("gitea", "clone", "ok", "ext::sh -c id"),
    ("gitea", "clone", "ok", "git@hote:-oProxyCommand=id"),
    ("migrate", "-oProxyCommand=id"),
])
def test_arguments_hostiles_refuses_avant_tout_geste(tmp_path, args):
    r = _ctl(_env(tmp_path), *args)
    assert r.returncode == REFUS, (args, r.returncode, r.stderr)
    assert "argument refuse" in r.stderr


@pytest.mark.parametrize("args", [
    ("app", "info", "mon_appli-2.v1"),
    ("app", "logs", "mon_appli", "50"),
    ("app", "archive", "mon_appli"),
    ("app", "archive", "--undeclared"),
    ("app", "wake-by-port", "8525", "--check"),
])
def test_arguments_legitimes_passent_la_garde(tmp_path, args):
    r = _ctl(_env(tmp_path), *args)
    assert r.returncode != REFUS, (args, r.stderr)
    assert "argument refuse" not in r.stderr


def test_git_clone_separe_les_options_du_depot():
    assert 'git clone -- "$repo" "$app_dir"' in CTL.read_text()
