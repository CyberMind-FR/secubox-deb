# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""Tests de la lecture anti-robots (#1216)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.antirobots import lire_anti_robots  # noqa: E402


def _profils(tmp_path, contenu):
    p = tmp_path / "vhost_profiles.json"
    p.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu))
    return p


def test_liste_lue_et_normalisee(tmp_path):
    p = _profils(tmp_path, {"anti_robots": ["Gitea.GK2.Secubox.in", " git.maegia.tv "]})
    assert lire_anti_robots(p) == {"gitea.gk2.secubox.in", "git.maegia.tv"}


def test_cle_absente_ne_coche_personne(tmp_path):
    """Un fichier antérieur à la fonctionnalité reste valide et ne filtre rien."""
    p = _profils(tmp_path, {"services": {}, "vhosts": {}})
    assert lire_anti_robots(p) == set()


def test_fichier_absent_est_silencieux(tmp_path):
    """Le panneau doit s'afficher même sans WAF installé : pas d'exception."""
    assert lire_anti_robots(tmp_path / "inexistant.json") == set()


def test_json_casse_est_silencieux(tmp_path):
    p = _profils(tmp_path, "{ ceci n'est pas du json")
    assert lire_anti_robots(p) == set()


def test_type_inattendu_est_silencieux(tmp_path):
    """anti_robots doit être une liste ; toute autre forme est ignorée."""
    p = _profils(tmp_path, {"anti_robots": "gitea.gk2.secubox.in"})
    assert lire_anti_robots(p) == set()


def test_entrees_vides_ecartees(tmp_path):
    p = _profils(tmp_path, {"anti_robots": ["", "  ", "gitea.gk2.secubox.in"]})
    assert lire_anti_robots(p) == {"gitea.gk2.secubox.in"}
