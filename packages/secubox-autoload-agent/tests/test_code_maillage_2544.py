# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2544 — Auto-Load dépose le code d'invitation du maillage ; la box l'installe au premier démarrage et la jonction se fait seule.

Même mécanique que le jeton (#2280) : fichier séparé sur /boot (jamais dans le fichier de réponses signé, qui n'est pas chiffré), installé en 0600
puis EFFACÉ de /boot. Le code ne donne AUCUN droit : le parent valide le jeton qu'il contient et décide."""
import base64
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE.parent / "secubox-premier-pas"))
sys.path.insert(0, str(RACINE.parent / "secubox-p2p"))

from autoload_agent import atelier as A, demarrage as D  # noqa: E402
from api import automesh  # noqa: E402

CODE = automesh.encoder("admin.gk2.secubox.in", "ab" * 32)


# ── Installation au démarrage ──────────────────────────────────────────────
def test_le_code_est_installe_en_0600_puis_efface_de_boot(tmp_path):
    src, dest = tmp_path / "boot" / "maillage", tmp_path / "p2p" / "automesh.code"
    src.parent.mkdir()
    src.write_text(CODE + "\n")
    assert D.installer_code_maillage(src, dest, proprietaire=None) == "installe"
    assert dest.read_text().strip() == CODE and stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert not src.exists() and stat.S_IMODE(dest.parent.stat().st_mode) == 0o700


def test_sans_fichier_sur_boot_rien_ne_change(tmp_path):
    assert D.installer_code_maillage(tmp_path / "absent", tmp_path / "p2p" / "automesh.code", proprietaire=None) == "absent"
    assert not (tmp_path / "p2p").exists()


@pytest.mark.parametrize("mauvais", ["", "x", "sbxmesh1.", "sbxmesh2.abc.1234", CODE[:-1], CODE + "\nautre", CODE.replace("sbxmesh1", "SBXMESH1"), " " + CODE + " x"])
def test_un_code_mal_forme_n_est_jamais_installe_et_reste_visible_a_l_atelier(tmp_path, mauvais):
    src, dest = tmp_path / "maillage", tmp_path / "p2p" / "automesh.code"
    src.write_text(mauvais)
    assert D.installer_code_maillage(src, dest, proprietaire=None) == "refuse" and not dest.exists() and src.exists()


def test_la_somme_de_controle_du_code_est_verifiee_quand_la_box_sait_la_lire(tmp_path):
    faux = CODE[:-4] + ("AAAA" if not CODE.endswith("AAAA") else "BBBB")
    src, dest = tmp_path / "maillage", tmp_path / "p2p" / "automesh.code"
    src.write_text(faux)
    assert D.installer_code_maillage(src, dest, proprietaire=None) == "refuse" and not dest.exists()


def test_un_code_deja_en_cours_n_est_pas_remplace(tmp_path):
    src, dest = tmp_path / "maillage", tmp_path / "p2p" / "automesh.code"
    dest.parent.mkdir(mode=0o700)
    dest.write_text("ancien\n")
    src.write_text(CODE)
    assert D.installer_code_maillage(src, dest, proprietaire=None) == "deja_present" and dest.read_text() == "ancien\n" and not src.exists()


def test_un_lien_symbolique_n_est_jamais_suivi(tmp_path):
    vrai = tmp_path / "vrai"
    vrai.write_text(CODE)
    src = tmp_path / "maillage"
    src.symlink_to(vrai)
    assert D.installer_code_maillage(src, tmp_path / "p2p" / "automesh.code", proprietaire=None) == "refuse" and vrai.exists()


def test_le_script_de_demarrage_installe_aussi_le_code():
    t = (RACINE / "sbin" / "autoload-agent-demarrage").read_text()
    assert "installer_code_maillage" in t and "code de maillage" in t


# ── Atelier ─────────────────────────────────────────────────────────────────
@pytest.fixture
def gnupg(tmp_path):
    home, pub = tmp_path / "gnupg", tmp_path / "provisioning.gpg"
    A.cle_init(home, pub)
    return home, pub


EXEMPLE = RACINE.parent / "secubox-premier-pas" / "exemples" / "reponses-autoload.toml"


def test_preparer_depose_le_code_en_0600_et_la_box_l_accepte(tmp_path, gnupg):
    home, pub = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    dossier = A.preparer(EXEMPLE, boot, home, pub, "gk2_" + "0123456789abcdef" * 2, code_maillage=CODE)
    f = dossier / "maillage"
    assert f.read_text().strip() == CODE and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert D.installer_code_maillage(f, tmp_path / "p2p" / "automesh.code", proprietaire=None) == "installe"


def test_preparer_refuse_un_code_mal_forme_avant_d_ecrire(tmp_path, gnupg):
    home, pub = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    with pytest.raises(A.AtelierErreur):
        A.preparer(EXEMPLE, boot, home, pub, "gk2_" + "0123456789abcdef" * 2, code_maillage="sbxmesh1.faux.0000")
    assert not (boot / "secubox").exists()


def test_la_commande_lit_le_code_sur_stdin_et_ne_l_affiche_jamais(tmp_path, gnupg):
    home, pub = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    p = subprocess.run([sys.executable, str(RACINE / "sbin" / "autoload-atelier"), "preparer", "--reponses", str(EXEMPLE), "--boot", str(boot),
                        "--homedir", str(home), "--trousseau", str(pub), "--code-maillage-stdin"], input=CODE + "\n", capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert CODE not in p.stdout + p.stderr and "code de maillage" in p.stdout and (boot / "secubox" / "autoload" / "maillage").is_file()


def test_verifier_dit_si_le_code_est_present(tmp_path, gnupg):
    home, pub = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    A.preparer(EXEMPLE, boot, home, pub, None, code_maillage=CODE)
    p = subprocess.run([sys.executable, str(RACINE / "sbin" / "autoload-atelier"), "verifier", "--boot", str(boot), "--trousseau", str(pub)], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "code de maillage présent" in p.stdout and CODE not in p.stdout
