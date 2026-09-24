# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/test_verify_profile.py
"""SecuBox-Deb :: une image ne sort que si son profil est installé (#1361).

L'image « full » alpha.5 ne contenait que `secubox-core` : l'installation du
méta-paquet avait échoué et la construction s'était contentée d'un `warn`. Au
premier démarrage — firstboot en échec, pas de MirrorNet, un kiosque qui
affichait « Welcome to nginx! » puis 403. Ces tests rejouent cet état sur un
faux rootfs, sans construire d'image.
"""
import pathlib
import subprocess

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "image" / "verify-profile.sh"

FULL = ("Depends: secubox-core (>= 1.4.3), secubox-hub, "
        "secubox-ndpid-engine, secubox-p2p | secubox-mesh\n")


def stanza(nom, statut="install ok installed", depends=""):
    return (f"Package: {nom}\nStatus: {statut}\nVersion: 1.0\n"
            f"Architecture: all\n{depends}Description: x\n\n")


def rootfs(tmp_path, *stanzas):
    admin = tmp_path / "var" / "lib" / "dpkg"
    admin.mkdir(parents=True)
    (admin / "status").write_text("".join(stanzas))
    (admin / "available").write_text("")
    for d in ("info", "updates"):
        (admin / d).mkdir()
    return tmp_path


def verifie(racine, profil="secubox-full"):
    return subprocess.run(["bash", str(SCRIPT), str(racine), profil],
                          capture_output=True, text=True)


def test_l_etat_reel_de_l_alpha5_est_refuse(tmp_path):
    """LE CAS VÉCU : seul secubox-core, pas de méta-paquet."""
    r = verifie(rootfs(tmp_path, stanza("secubox-core")))
    assert r.returncode == 1
    assert "PROFIL NON INSTALLÉ" in r.stderr


def test_un_profil_complet_passe(tmp_path):
    r = verifie(rootfs(tmp_path,
        stanza("secubox-full", depends=FULL),
        stanza("secubox-core"), stanza("secubox-hub"),
        stanza("secubox-ndpid-engine"), stanza("secubox-p2p")))
    assert r.returncode == 0, r.stderr


def test_une_dependance_manquante_est_nommee(tmp_path):
    """Le méta-paquet forcé sans ndpid-engine : il faut dire LEQUEL manque."""
    r = verifie(rootfs(tmp_path,
        stanza("secubox-full", depends=FULL),
        stanza("secubox-core"), stanza("secubox-hub"), stanza("secubox-p2p")))
    assert r.returncode == 1
    assert "secubox-ndpid-engine" in r.stderr


def test_une_alternative_suffit(tmp_path):
    r = verifie(rootfs(tmp_path,
        stanza("secubox-full", depends=FULL),
        stanza("secubox-core"), stanza("secubox-hub"),
        stanza("secubox-ndpid-engine"), stanza("secubox-mesh")))
    assert r.returncode == 0, r.stderr


def test_un_paquet_a_moitie_installe_est_refuse(tmp_path):
    """`dpkg -i --force-depends` laisse des paquets dépaquetés mais non
    configurés : ça ne se voit qu'au démarrage, quand leur service manque."""
    r = verifie(rootfs(tmp_path,
        stanza("secubox-full", depends=FULL),
        stanza("secubox-core"), stanza("secubox-hub"), stanza("secubox-p2p"),
        stanza("secubox-ndpid-engine", statut="install ok unpacked")))
    assert r.returncode == 1
    assert "secubox-ndpid-engine" in r.stderr


def test_la_construction_n_avale_plus_l_echec_du_profil():
    """Le `|| warn` qui a produit l'alpha.5 ne doit pas revenir."""
    src = (SCRIPT.parent / "build-image.sh").read_text()
    assert 'warn "${SECUBOX_PROFILE} non disponible"' not in src
    assert "verify-profile.sh" in src
