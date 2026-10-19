# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Sonde de secours (dead-man switch) du pseudo-routeur (ref #2940, Tache 1).

Independante du ctl qui bascule la passerelle : si gk2 cesse de transferer, le retour
a la Freebox doit se declencher meme si le service qui l'a decide a lui-meme plante."""
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "sonde-secours"


def _etat(tmp_path, env=None):
    e = dict(env or {}, SECUBOX_SONDE_ETAT=str(tmp_path / "sonde.json"))
    subprocess.run(["bash", str(SCRIPT), "verifier"], env=e, capture_output=True, text=True)
    return json.loads((tmp_path / "sonde.json").read_text())


def test_trois_echecs_consecutifs_marquent_inactif(tmp_path, monkeypatch):
    faux_sonde = tmp_path / "bin" / "ping"
    faux_sonde.parent.mkdir()
    faux_sonde.write_text("#!/bin/sh\nexit 1\n")
    faux_sonde.chmod(0o755)
    env = {"PATH": f"{faux_sonde.parent}:/usr/bin:/bin"}
    for _ in range(3):
        etat = _etat(tmp_path, env)
    assert etat["echecs_consecutifs"] == 3
    assert etat["actif"] is False


def test_un_succes_reinitialise_le_compteur(tmp_path):
    faux_bin = tmp_path / "bin"
    faux_bin.mkdir()
    (faux_bin / "ping").write_text("#!/bin/sh\nexit 1\n")
    (faux_bin / "ping").chmod(0o755)
    env = {"PATH": f"{faux_bin}:/usr/bin:/bin"}
    _etat(tmp_path, env)
    _etat(tmp_path, env)
    (faux_bin / "ping").write_text("#!/bin/sh\nexit 0\n")
    etat = _etat(tmp_path, env)
    assert etat["echecs_consecutifs"] == 0
    assert etat["actif"] is True


def test_echec_arme_le_minuteur_de_retour_independamment():
    """Le minuteur qui REND la main a la Freebox doit etre arme par un service SEPARE
    de celui qui echoue, pour se declencher meme si le service de sonde plante net.

    Ruling (ecart de plan, Tache 1 etape 5) : la brief pointe vers un chemin installe
    (/usr/lib/secubox/pseudo-routeur/...) qui n'existe jamais dans un arbre source. Le
    fichier source reel est packages/secubox-pseudo-routeur/systemd/..., cite tel quel
    dans la liste de Fichiers du plan — c'est ce chemin qu'on teste."""
    unite = Path(__file__).resolve().parents[1] / "systemd" / "pseudo-routeur-sonde.service"
    assert unite.exists()
    texte = unite.read_text()
    assert "pseudo-routeur-retour.timer" not in texte, (
        "le retour ne doit pas etre arme DANS le service de sonde (sinon un crash du "
        "service de sonde empeche aussi le retour) : il vit dans sa propre unite, "
        "reveillee par OnFailure= du service de sonde ET par le timer regulier"
    )
