# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2190 : application du tunnel par sudo à argv exact (le service n'est pas root, aucune nouvelle unité root)."""
import subprocess
from pathlib import Path

import pytest

from autoload import tunnel as T

ICI = Path(__file__).resolve().parents[1]


class R:
    def __init__(self, rc=0, err=""):
        self.returncode, self.stdout, self.stderr = rc, "", err


def test_l_argv_est_exact_avec_delai():
    vus = []

    def ex(argv, **kw):
        vus.append((argv, kw))
        return R()
    T.appliquer_par_sudo(ex)
    assert vus[0][0] == ["sudo", "-n", "/usr/sbin/autoloadctl", "tunnel-sync"] and vus[0][1].get("timeout")


def test_le_sudoers_accorde_exactement_ces_argv_et_rien_d_autre():
    """Deux argv exacts : tunnel-sync (enrôlement, révocation, abonnement) et tunnel-sync --horaire (minuterie, #3126 N4)."""
    lignes = [x for x in (ICI / "sudoers.d" / "secubox-autoload").read_text().splitlines() if x and not x.startswith("#")]
    assert lignes == ["secubox-autoload ALL=(root) NOPASSWD: /usr/sbin/autoloadctl tunnel-sync",
                      "secubox-autoload ALL=(root) NOPASSWD: /usr/sbin/autoloadctl tunnel-sync --horaire"]
    assert lignes[0].endswith(" " + " ".join(T.SUDO_SYNC[2:])) and lignes[1].endswith(" " + " ".join(T.SUDO_SYNC_HORAIRE[2:]))


@pytest.mark.parametrize("exc", [OSError("introuvable"), subprocess.TimeoutExpired("sudo", 30)])
def test_un_echec_systeme_devient_une_erreur_de_tunnel(exc):
    def ex(argv, **kw):
        raise exc
    with pytest.raises(T.TunnelErreur):
        T.appliquer_par_sudo(ex)


def test_un_refus_de_sudo_est_signale():
    with pytest.raises(T.TunnelErreur, match="refusée"):
        T.appliquer_par_sudo(lambda argv, **kw: R(1, "sudo: a password is required"))


def test_l_unite_garde_sudo_possible_sans_root():
    """NoNewPrivileges=no est requis (sinon sudo est neutralisé) ; les options qui l'imposent par seccomp en sont ABSENTES (précédent voicestudio, #1917)."""
    u = (ICI / "systemd" / "secubox-autoload.service").read_text()
    reel = [x for x in u.splitlines() if x and not x.startswith("#")]
    assert "NoNewPrivileges=no" in reel and "User=secubox-autoload" in reel
    for interdit in ("ProtectKernelTunables", "RestrictSUIDSGID", "LockPersonality", "RestrictNamespaces", "SystemCallFilter", "MemoryDenyWriteExecute",
                     "RestrictAddressFamilies", "ProtectKernelModules", "ProtectKernelLogs", "PrivateDevices"):
        assert not any(x.startswith(interdit + "=") for x in reel), interdit
    assert not any(x.startswith("User=root") for x in reel)
    assert not (ICI / "systemd" / "secubox-autoload-sync.service").exists()                   # aucune nouvelle unité root
