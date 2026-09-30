# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""jellyfinctl refuse les arguments hostiles (#1785).

Le script tourne en root par sudo avec TOUT argument : ses propres gardes
sont les seules. Le vrai script est lancé dans un bac à sable (configuration
LXC factice, `lxc-info` et `curl` doublés).
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "jellyfinctl")
LIGNES = [
    "lxc.rootfs.path = dir:/x\n",
    "lxc.mount.entry = /data/shared/photos media/photoprism none bind,ro,create=dir 0 0\n",
    "lxc.mount.entry = /data/nc media/nextcloud none bind,ro,create=dir 0 0\n",
]


def _exe(p: Path, corps: str):
    p.write_text("#!/usr/bin/env bash\n" + corps)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def banc(tmp_path):
    lxc = tmp_path / "lxc" / "jellyfin"
    lxc.mkdir(parents=True)
    (lxc / "config").write_text("".join(LIGNES))
    conf = tmp_path / "jellyfin.toml"
    conf.write_text(f'[lxc]\nname = "jellyfin"\npath = "{tmp_path}/lxc"\n')
    b = tmp_path / "bin"
    b.mkdir()
    _exe(b / "lxc-info", 'echo "State:          STOPPED"\n')
    _exe(b / "curl", "exit 22\n")
    env = dict(os.environ,
               PATH=f"{b}:{os.environ['PATH']}",
               SECUBOX_JELLYFIN_CONFIG=str(conf),
               SECUBOX_JELLYFIN_STATE_DIR=str(tmp_path / "etat"),
               SECUBOX_SECRETS_DIR=str(tmp_path / "secrets"))
    (tmp_path / "etat").mkdir()
    return tmp_path, lxc / "config", env


def _ctl(env, *args):
    return subprocess.run(["bash", CTL, *args], env=env, capture_output=True, text=True, timeout=30)


def test_unwire_n_execute_jamais_un_nom_fabrique(banc):
    tmp, cfg, env = banc
    temoin = tmp / "injection-executee"
    r = _ctl(env, "partner", "unwire", f"photoprism#e touch {temoin} #")
    assert r.returncode == 64, r.stderr
    assert not temoin.exists(), "le nom a été exécuté par sed (commande e)"
    assert cfg.read_text() == "".join(LIGNES)


@pytest.mark.parametrize("nom", ["inconnu", "../../../../", "-x"])
def test_unwire_refuse_un_partenaire_inconnu(banc, nom):
    _, cfg, env = banc
    assert _ctl(env, "partner", "unwire", nom).returncode == 64
    assert cfg.read_text() == "".join(LIGNES)


def test_unwire_d_un_partenaire_connu_retire_sa_seule_ligne(banc):
    _, cfg, env = banc
    r = _ctl(env, "partner", "unwire", "photoprism")
    assert r.returncode == 0, r.stderr
    assert cfg.read_text() == LIGNES[0] + LIGNES[2]


@pytest.mark.parametrize("nom", ["x'; DROP TABLE ApiKeys; --", "a b", "é", "x" * 65])
def test_apikey_mint_refuse_un_nom_hors_grammaire(banc, nom):
    _, _, env = banc
    r = _ctl(env, "apikey-mint", nom)
    assert r.returncode == 64, (nom, r.returncode, r.stderr)
