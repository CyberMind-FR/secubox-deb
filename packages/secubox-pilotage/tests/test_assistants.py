# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126), round 1 : les deux assistants root du paquet — dossier de données par descripteur (I3), ACL du journal d'audit (I4/R25)."""
import grp
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
INIT = ICI / "init_donnees.py"
ACL = ICI / "sbin" / "secubox-pilotage-audit-acl"
MOI = pwd.getpwuid(os.getuid()).pw_name
MON_GROUPE = grp.getgrgid(os.getgid()).gr_name


def _init(parent, *extra):
    return subprocess.run([sys.executable, "-I", str(INIT), str(parent), "pilotage", MOI, *extra], capture_output=True, text=True)


def test_dossier_cree_0750_au_bon_compte(tmp_path):
    r = _init(tmp_path)
    assert r.returncode == 0, r.stderr
    d = tmp_path / "pilotage"
    assert d.is_dir() and not d.is_symlink() and stat.S_IMODE(d.stat().st_mode) == 0o750 and d.stat().st_uid == os.getuid()


def test_dossier_existant_resserre_et_contenu_garde(tmp_path):
    d = tmp_path / "pilotage"
    d.mkdir(mode=0o777)
    d.chmod(0o777)
    (d / "pilotage.db").write_text("x")
    assert _init(tmp_path).returncode == 0
    assert stat.S_IMODE(d.stat().st_mode) == 0o750 and (d / "pilotage.db").read_text() == "x"


def test_lien_plante_cible_intacte(tmp_path):
    cible = tmp_path / "cible"
    cible.mkdir(mode=0o755)
    cible.chmod(0o755)
    (cible / "secret").write_text("s")
    (tmp_path / "pilotage").symlink_to(cible)
    r = _init(tmp_path)
    assert r.returncode == 0, r.stderr
    d = tmp_path / "pilotage"
    assert d.is_dir() and not d.is_symlink()                              # le lien est remplacé par un vrai dossier
    assert stat.S_IMODE(cible.stat().st_mode) == 0o755 and (cible / "secret").read_text() == "s"   # la cible n'a pas bougé


def test_parent_lien_refuse(tmp_path):
    reel = tmp_path / "reel"
    reel.mkdir()
    (tmp_path / "parent").symlink_to(reel)
    r = _init(tmp_path / "parent")
    assert r.returncode != 0 and not (reel / "pilotage").exists()


def test_fichier_a_la_place_du_dossier_refuse(tmp_path):
    (tmp_path / "pilotage").write_text("fichier")
    r = _init(tmp_path)
    assert r.returncode != 0 and (tmp_path / "pilotage").read_text() == "fichier"


def test_init_sans_chemin_shell():
    texte = INIT.read_text()
    assert "O_NOFOLLOW" in texte and "dir_fd" in texte and "fchown" in texte and "fchmod" in texte
    assert "os.chown(" not in texte.replace("os.fchown(", "") and "os.chmod(" not in texte.replace("os.fchmod(", "")


# ---------------------------------------------------------------- ACL du journal d'audit


@pytest.fixture()
def acl(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    faux = bin_ / "setfacl"
    faux.write_text('#!/bin/sh\necho "$@" >> "$BANC_APPELS"\nfor a; do last="$a"; done\n[ -e "$last" ] || exit 3\n')
    faux.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "BANC_APPELS": str(tmp_path / "appels")}

    def lancer(fichier, proprietaire=MOI, pour="nobody"):
        return subprocess.run([sys.executable, "-I", str(ACL), "--fichier", str(fichier), "--proprietaire", proprietaire, "--pour", pour],
                              env=env, capture_output=True, text=True)

    lancer.appels = lambda: (tmp_path / "appels").read_text() if (tmp_path / "appels").exists() else ""
    return lancer


def test_acl_posee_sur_fichier_regulier_du_proprietaire(acl, tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("")
    r = acl(f)
    assert r.returncode == 0, r.stderr
    appel = acl.appels()
    assert "-m u:nobody:rw-" in appel and "/proc/self/fd/" in appel          # sur le descripteur vérifié, jamais sur le chemin
    assert str(f) not in appel


def test_acl_refusee_sur_lien_plante(acl, tmp_path):
    cible = tmp_path / "cible"
    cible.write_text("")
    f = tmp_path / "audit.log"
    f.symlink_to(cible)
    r = acl(f)
    assert r.returncode != 0 and acl.appels() == ""


def test_acl_refusee_si_plusieurs_liens_durs(acl, tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("")
    os.link(f, tmp_path / "autre")
    assert acl(f).returncode != 0 and acl.appels() == ""


def test_acl_refusee_si_autre_proprietaire(acl, tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("")
    autre = "root" if MOI != "root" else "nobody"
    assert acl(f, proprietaire=autre).returncode != 0 and acl.appels() == ""


def test_acl_refusee_si_pas_un_fichier_regulier(acl, tmp_path):
    d = tmp_path / "audit.log"
    d.mkdir()
    assert acl(d).returncode != 0 and acl.appels() == ""


def test_acl_fichier_absent_pas_d_erreur_bruyante(acl, tmp_path):
    r = acl(tmp_path / "absent.log")
    assert r.returncode == 0 and acl.appels() == ""                          # rien à faire tant que secubox-core n'a pas créé le journal
