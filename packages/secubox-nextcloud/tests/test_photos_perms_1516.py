# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Dossiers photo partagés : plus de 0777, UID mesurés, jamais récursif (#1516)."""
import os
import re
import stat
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
CTL = (PKG / "sbin" / "nextcloudctl").read_text()
PPCTL = (PKG.parent / "secubox-photoprism" / "sbin" / "photoprismctl").read_text()


def test_plus_aucun_0777_dans_les_scripts():
    for nom, texte in (("nextcloudctl", CTL), ("photoprismctl", PPCTL)):
        code = [l for l in texte.splitlines() if "0777" in l and not l.lstrip().startswith("#")]
        assert code == [], (nom, code)


def test_uid_mesures_et_modes():
    assert "SBX_UID_NC=100033" in CTL and "SBX_UID_LXC=100000" in CTL and "SBX_GID_PP=100995" in CTL
    assert "chmod 2750" in CTL and "chmod 0755" in CTL
    assert "chown 100033:100995" in PPCTL and "chmod 2750" in PPCTL


def _extrait():
    """Les fonctions photos_perms_* du script, chargeables seules."""
    m = re.search(r"SBX_UID_NC=.*?^photos_perms_reparer\(\) \{.*?^\}\n", CTL, re.S | re.M)
    assert m
    return m.group(0)


def test_aucun_0777_dans_les_autres_points_de_creation():
    # postinst photoprism et install-lxc.sh remettaient la racine en 0777 après le correctif.
    for rel in ("secubox-photoprism/debian/postinst", "secubox-photoprism/lib/photoprism/install-lxc.sh"):
        code = [l for l in (PKG.parent / rel).read_text().splitlines()
                if "0777" in l and not l.lstrip().startswith("#")]
        assert code == [], (rel, code)


def test_reparer_resserre_sans_recursion(tmp_path):
    shim = tmp_path / "bin"
    shim.mkdir()
    journal = tmp_path / "chown.log"
    (shim / "chown").write_text(f'#!/bin/sh\necho "$@" >> {journal}\n')      # pas root : on enregistre
    (shim / "chown").chmod(0o755)
    racine = tmp_path / "photos"
    user = racine / "gk2"
    profond = user / "album" / "x"
    profond.mkdir(parents=True)
    for d in (racine, user):
        d.chmod(0o777)
    (user / "album").chmod(0o777)
    (user / "photo.jpg").write_text("x")
    script = _extrait() + f'\nSHARED_PHOTOS={racine}\nphotos_perms_reparer\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={**os.environ, "PATH": f"{shim}:{os.environ['PATH']}"})
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(racine.stat().st_mode) == 0o755
    assert stat.S_IMODE(user.stat().st_mode) == 0o2750
    assert stat.S_IMODE((user / "album").stat().st_mode) == 0o777        # plus profond : intact
    assert stat.S_IMODE((user / "photo.jpg").stat().st_mode) != 0o2750  # le contenu n'est pas touché
    ch = journal.read_text()
    assert f"100033:100995 {user}" in ch and f"100000:100000 {racine}" in ch
    assert "album" not in ch                                             # jamais récursif
