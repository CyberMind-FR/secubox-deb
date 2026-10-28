# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3240 — nDPIsrvd en boucle sur une box sans toolbox.

CONSTAT (ESPRESSObin v7 en minimal, 2026-10-28) : l'unité passait `-G secubox-ndpi:secubox-toolbox` ; sans le paquet toolbox,
le groupe n'existe pas, nDPIsrvd sort en 1 (« Could not chmod/chown … No such file or directory »), `Restart=on-failure` le
relance toutes les 3 s et le moteur (`Requires=`) tombe avec lui. Le lanceur donne le socket distributeur au groupe lecteur
s'il existe, sinon le laisse au groupe du producteur : personne d'autre ne le lit, et nDPIsrvd tourne."""
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
LANCEUR = PKG / "sbin" / "secubox-ndpisrvd-run"
UNITE = PKG / "systemd" / "secubox-ndpisrvd.service"
REGLES = PKG / "debian" / "rules"


@pytest.fixture
def banc(tmp_path):
    appels = tmp_path / "appels.txt"
    srvd = tmp_path / "nDPIsrvd"
    srvd.write_text(f"#!/bin/sh\necho \"$@\" > {appels}\n")
    srvd.chmod(0o755)
    groupes = tmp_path / "groupes"
    # faux getent : rend 0 pour les groupes listés, 2 sinon (comme getent pour une clé absente)
    getent = tmp_path / "getent"
    getent.write_text(f"#!/bin/sh\n[ \"$1\" = group ] && grep -qx \"$2\" {groupes} && {{ echo \"$2:x:1:\"; exit 0; }}\nexit 2\n")
    getent.chmod(0o755)

    def lance(existants, lecteur="secubox-toolbox"):
        groupes.write_text("".join(g + "\n" for g in existants))
        env = {"PATH": "/usr/bin:/bin", "SECUBOX_NDPISRVD_BIN": str(srvd), "SECUBOX_GETENT_CMD": str(getent),
               "COLLECTEUR": "/run/c.sock", "DISTRIBUTEUR": "/run/d.sock", "UTILISATEUR": "u", "GROUPE": "g",
               "GROUPE_LECTEUR": lecteur}
        r = subprocess.run(["sh", str(LANCEUR)], capture_output=True, text=True, env=env, timeout=20)
        return r, (appels.read_text().strip() if appels.exists() else None)
    return lance


def test_groupe_lecteur_present_il_recoit_le_socket(banc):
    r, args = banc(["g", "secubox-toolbox"])
    assert r.returncode == 0 and args == "-l -c /run/c.sock -s /run/d.sock -u u -g g -G u:secubox-toolbox"


def test_groupe_lecteur_absent_le_socket_reste_au_producteur(banc):
    """LE CAS DE L'ESPRESSObin minimal : pas de toolbox, pas de groupe secubox-toolbox."""
    r, args = banc(["g"])
    assert r.returncode == 0 and args == "-l -c /run/c.sock -s /run/d.sock -u u -g g -G u:g"
    assert "secubox-toolbox" in r.stderr and "n'existe pas" in r.stderr


def test_groupe_lecteur_vide_le_socket_reste_au_producteur(banc):
    r, args = banc(["g", "secubox-toolbox"], lecteur="")
    assert r.returncode == 0 and args == "-l -c /run/c.sock -s /run/d.sock -u u -g g -G u:g"


def test_l_unite_passe_par_le_lanceur():
    texte = UNITE.read_text()
    assert "ExecStart=/usr/sbin/secubox-ndpisrvd-run" in texte
    assert "-G ${UTILISATEUR}:${GROUPE_LECTEUR}" not in texte


def test_le_paquet_installe_le_lanceur():
    assert "sbin/secubox-ndpisrvd-run" in REGLES.read_text()
