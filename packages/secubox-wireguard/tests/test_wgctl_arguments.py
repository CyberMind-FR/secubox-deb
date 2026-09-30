# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""wgctl refuse les arguments hostiles et ne livre plus de secret (#1785).

Le script tourne en root par sudo avec tout argument. Le vrai script, avec
`wg`, `wg-quick`, `ssh` et `rsync` doublés.
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "wgctl"
PRIVEE = "cPrivateKeyOfTheServerxxxxxxxxxxxxxxxxxxxx="
PARTAGEE = "pPresharedKeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="
PUB = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/abcde="  # 43 + "=", comme une vraie clé
DUMP = (f"wg0\t{PRIVEE}\tpubSrv=\t51820\toff\n"
        f"wg0\t{PUB}\t{PARTAGEE}\t1.2.3.4:5\t10.0.0.2/32\t0\t10\t20\toff\n"
        f"wg1\t(none)\tpub1=\t51821\toff\n"
        f"wg1\tpub2=\t(none)\t(none)\t10.0.1.2/32\t0\t0\t0\t25\n")


def _exe(p: Path, corps: str):
    p.write_text("#!/usr/bin/env bash\n" + corps)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def env(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    (tmp_path / "dump.txt").write_text(DUMP)
    _exe(b / "wg", f'if [ "$*" = "show all dump" ]; then cat "{tmp_path}/dump.txt"; exit 0; fi; exit 1\n')
    for outil in ("wg-quick", "ssh", "rsync", "qrencode"):
        _exe(b / outil, f'echo "$0 $*" >> "{tmp_path}/lances.txt"; exit 1\n')
    return dict(os.environ, PATH=f"{b}:{os.environ['PATH']}")


def _ctl(env, *args):
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("args", [
    ("peer", "config", "../../../../etc/wireguard/wg0"),
    ("peer", "qr", "../x"),
    ("peer", "add", "../../etc/wireguard/pose"),
    ("peer", "add", "alice", "../../tmp/x"),
    ("peer", "remove", "../x"),
    ("interface", "up", "/tmp/piege.conf"),
    ("interface", "down", "wg0;id"),
    ("interface", "up", "une-interface-trop-longue"),
])
def test_arguments_hostiles_refuses(env, args):
    r = _ctl(env, *args)
    assert r.returncode == 64, (args, r.returncode, r.stdout + r.stderr)


@pytest.mark.parametrize("args", [
    ("peer", "remove", PUB),
    ("peer", "remove", "alice.laptop", "wg0"),
    ("peer", "config", "alice"),
])
def test_arguments_legitimes_passent_la_garde(env, args):
    r = _ctl(env, *args)
    assert r.returncode != 64, (args, r.stdout + r.stderr)
    assert "argument refusé" not in r.stdout + r.stderr


def test_migrate_refuse_par_le_chemin_sudo_d_un_compte_de_service(env, tmp_path):
    r = _ctl(dict(env, SUDO_USER="secubox"), "migrate", "attaquant.example")
    assert r.returncode == 64
    assert not (tmp_path / "lances.txt").exists(), "ssh/rsync lancé malgré le refus"


def test_dump_masque_les_secrets_et_garde_le_format(env):
    r = _ctl(env, "dump")
    assert r.returncode == 0, r.stderr
    assert PRIVEE not in r.stdout and PARTAGEE not in r.stdout
    lignes = [l.split("\t") for l in r.stdout.strip().splitlines()]
    assert [len(l) for l in lignes] == [5, 9, 5, 9]
    assert lignes[0][1] == "(masquée)" and lignes[0][2] == "pubSrv="
    assert lignes[1][1] == PUB and lignes[1][2] == "(masquée)" and lignes[1][6] == "10"
    assert lignes[2][1] == "(none)" and lignes[3][2] == "(none)"


def test_sudoers_ne_donne_plus_wg_show():
    s = (CTL.parents[1] / "debian" / "secubox-wireguard.sudoers").read_text()
    regles = [l for l in s.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert regles == ["secubox ALL=(root) NOPASSWD: /usr/sbin/wgctl"]
