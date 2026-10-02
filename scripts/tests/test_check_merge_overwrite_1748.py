# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde-fou contre les fusions qui écrasent master (#1748), sur de vrais dépôts jetables."""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check-merge-overwrite.sh"
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@x", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


def git(depot, *args, check=True):
    return subprocess.run(["git", *args], cwd=depot, env=ENV, capture_output=True, text=True, check=check)


def ecrit(depot, nom, texte):
    p = depot / nom
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(texte)
    git(depot, "add", nom)
    git(depot, "commit", "-q", "-m", f"edit {nom}")


@pytest.fixture
def depot(tmp_path):
    git(tmp_path, "init", "-q", "-b", "master")
    ecrit(tmp_path, "m/api/main.py", "\n".join(f"l{i}" for i in range(40)) + "\n")
    return tmp_path


def lance(depot, *args):
    return subprocess.run([str(SCRIPT), *args], cwd=depot, env=ENV, capture_output=True, text=True)


def branche_et_master_divergent(depot):
    # Les deux côtés modifient LA MÊME ligne : un conflit, résolu en « prendre le leur ».
    git(depot, "checkout", "-q", "-b", "ancienne")
    lignes = [f"l{i}" for i in range(40)]
    lignes[0] = "version ancienne"
    ecrit(depot, "m/api/main.py", "\n".join(lignes) + "\n")
    git(depot, "checkout", "-q", "master")
    lignes = [f"l{i}" for i in range(40)]
    lignes[0] = "travail de master"
    ecrit(depot, "m/api/main.py", "\n".join(lignes) + "\n")


def test_fusion_qui_prend_la_version_de_la_branche_est_detectee(depot):
    branche_et_master_divergent(depot)
    git(depot, "merge", "-q", "--no-ff", "-s", "ort", "-X", "theirs", "ancienne", "-m", "fusion ecrasante", check=False)
    r = lance(depot, "--commit", "HEAD")
    assert r.returncode == 1 and "m/api/main.py" in r.stdout


def test_vraie_fusion_a_trois_voies_passe(depot):
    # master et la branche touchent des zones différentes : la fusion n'est ni l'un ni l'autre.
    git(depot, "checkout", "-q", "-b", "feat")
    lignes = [f"l{i}" for i in range(40)]
    lignes[39] = "fin modifiee par la branche"
    ecrit(depot, "m/api/main.py", "\n".join(lignes) + "\n")
    git(depot, "checkout", "-q", "master")
    lignes = [f"l{i}" for i in range(40)]
    lignes[0] = "debut modifie par master"
    ecrit(depot, "m/api/main.py", "\n".join(lignes) + "\n")
    git(depot, "merge", "-q", "--no-ff", "feat", "-m", "fusion propre")
    r = lance(depot, "--commit", "HEAD")
    assert r.returncode == 0 and r.stdout == ""


def test_fichier_modifie_d_un_seul_cote_passe(depot):
    git(depot, "checkout", "-q", "-b", "feat")
    ecrit(depot, "m/api/main.py", "autre contenu\n")
    git(depot, "checkout", "-q", "master")
    ecrit(depot, "autre.py", "x\n")
    git(depot, "merge", "-q", "--no-ff", "feat", "-m", "fusion")
    assert lance(depot, "--commit", "HEAD").returncode == 0


def test_plage_ne_regarde_que_les_fusions_de_la_pr(depot):
    branche_et_master_divergent(depot)
    base = git(depot, "rev-parse", "HEAD").stdout.strip()
    git(depot, "merge", "-q", "--no-ff", "-X", "theirs", "ancienne", "-m", "fusion ecrasante", check=False)
    assert lance(depot, "--range", f"{base}..HEAD").returncode == 1        # la fusion est dans la plage
    assert lance(depot, "--range", "HEAD..HEAD").returncode == 0           # plage vide : rien


def test_historique_complet(depot):
    branche_et_master_divergent(depot)
    git(depot, "merge", "-q", "--no-ff", "-X", "theirs", "ancienne", "-m", "fusion ecrasante", check=False)
    assert lance(depot, "--since", "2000-01-01", "--ref", "HEAD").returncode == 1


def test_usage_invalide():
    assert subprocess.run([str(SCRIPT), "--nimporte"], capture_output=True).returncode == 2
