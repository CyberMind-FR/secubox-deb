# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""nextcloudctl ne se laisse pas piloter par des arguments fabriqués (#1785).

Le script tourne en root par sudo avec tout argument. Ici le vrai script, avec
`lxc-attach` et `lxc-info` doublés : on regarde ce qu'il LANCE.
"""
import os
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "nextcloudctl"


def _exe(p: Path, corps: str):
    p.write_text("#!/usr/bin/env bash\n" + corps)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def banc(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    lances = tmp_path / "lances.txt"
    # Chaque argument sur sa ligne : l'argv exact reçu par lxc-attach.
    _exe(b / "lxc-attach", f'printf "%s\\n" "$@" > "{lances}"; printf -- "---\\n" >> "{lances}"\n')
    _exe(b / "lxc-info", 'echo "State:          RUNNING"\n')
    data = tmp_path / "data"
    (data / "backups").mkdir(parents=True)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}",
               SECUBOX_LXC_PATH=str(tmp_path / "lxc"), SECUBOX_NEXTCLOUD_DATA=str(data))
    return tmp_path, env, lances


def _ctl(env, *args, stdin=""):
    return subprocess.run(["bash", str(CTL), *args], env=env, input=stdin,
                          capture_output=True, text=True, timeout=30)


def test_restore_refuse_un_chemin_libre(banc):
    tmp, env, _ = banc
    piege = tmp / "piege.tar.gz"
    with tarfile.open(piege, "w:gz") as t:
        f = tmp / "fichier"
        f.write_text("x")
        t.add(f, arcname="ecrase-moi")
    r = _ctl(env, "restore", str(piege), stdin="yes\n")
    assert r.returncode != 0
    assert not (tmp / "data" / "ecrase-moi").exists(), "archive libre extraite"


def test_logs_n_injecte_rien(banc):
    _, env, lances = banc
    _ctl(env, "logs", "5; touch /tmp/x")
    argv = lances.read_text().splitlines()
    assert argv[-5:-1] == ["tail", "-n", "50", "/var/log/nginx/error.log"], argv


@pytest.mark.parametrize("app", ["x; id", "../x", "A-B", ""])
def test_app_install_refuse_un_identifiant_hors_grammaire(banc, app):
    _, env, lances = banc
    r = _ctl(env, "app", "install", app)
    assert r.returncode != 0
    assert not lances.exists() or "occ" not in lances.read_text()


def test_setup_refuse_par_le_chemin_sudo_d_un_compte_de_service(banc):
    _, env, lances = banc
    r = _ctl(dict(env, SUDO_USER="secubox"), "setup", "x' ; id ; '")
    assert r.returncode == 64
    assert not lances.exists()


def test_occ_passe_ses_arguments_en_argv_jamais_dans_une_chaine_de_shell():
    src = CTL.read_text()
    assert 'lxc_attach_argv sudo -u www-data php /var/www/nextcloud/occ "$@"' in src
    assert 'occ $*"' not in src
