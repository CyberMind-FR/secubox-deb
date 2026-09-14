# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Profils vocaux (#1287) — « Billets chaleureuse, Sentinel neutre ».

Le point délicat n'est pas de rendre la bonne voix : c'est de ne JAMAIS remplacer
une voix silencieusement. Une alerte de sécurité lue par la voix d'animateur est
une erreur qu'il vaut mieux voir passer qu'ignorer.
"""
import json

import pytest

from api import profils as mod
from api.profils import Profils


@pytest.fixture
def sans_manifestes(monkeypatch, tmp_path):
    """Isole des manifestes réellement installés sur la machine de test."""
    monkeypatch.setattr(mod, "CAP_DIR", str(tmp_path))
    return tmp_path


def test_profil_connu_rend_sa_voix_sans_avertir(sans_manifestes):
    p = Profils({"voix_defaut": "lexie-fr",
                 "profils": {"billets": {"voix": "chaleureuse"}}})
    voix, avert = p.resoud("billets")
    assert voix == "chaleureuse"
    assert avert is None


def test_profil_inconnu_rend_le_defaut_MAIS_le_dit(sans_manifestes):
    p = Profils({"voix_defaut": "lexie-fr"})
    voix, avert = p.resoud("sentinel")
    assert voix == "lexie-fr"
    assert avert and "sentinel" in avert
    # L'avertissement doit expliquer QUOI FAIRE, pas seulement constater.
    assert "voice.toml" in avert or "manifeste" in avert


def test_absence_de_profil_demande_nest_pas_un_avertissement(sans_manifestes):
    """Ne rien demander est légitime : on ne harcèle pas l'appelant."""
    voix, avert = Profils({"voix_defaut": "lexie-fr"}).resoud(None)
    assert voix == "lexie-fr" and avert is None


@pytest.mark.parametrize("mechant", [
    "../../etc/passwd", "a/b", "AVEC-MAJUSCULES", "a" * 60, "", "x;rm -rf /",
])
def test_nom_de_profil_hors_format_est_refuse(sans_manifestes, mechant):
    p = Profils({"voix_defaut": "lexie-fr"})
    voix, avert = p.resoud(mechant)
    assert voix == "lexie-fr"
    if mechant:
        assert avert is not None


def test_une_voix_hors_format_dans_un_manifeste_est_ignoree(sans_manifestes):
    """Un manifeste vient d'un paquet, mais un paquet mal formé ne doit pas
    pouvoir injecter un chemin dans le nom de fichier de voix."""
    (sans_manifestes / "mechant.json").write_text(json.dumps({
        "service": "mechant",
        "profils": {"piege": {"voix": "../../../etc/shadow"}},
    }), encoding="utf-8")
    p = Profils({"voix_defaut": "lexie-fr"})
    assert "piege" not in {x["nom"] for x in p.liste()}
    voix, avert = p.resoud("piege")
    assert voix == "lexie-fr" and avert is not None


def test_la_config_gagne_sur_le_manifeste(sans_manifestes):
    """L'opérateur a le dernier mot sur la voix de sa box."""
    (sans_manifestes / "billets.json").write_text(json.dumps({
        "service": "billets",
        "profils": {"billets": {"voix": "voix-du-paquet"}},
    }), encoding="utf-8")
    p = Profils({"voix_defaut": "lexie-fr",
                 "profils": {"billets": {"voix": "voix-de-l-operateur"}}})
    assert p.resoud("billets")[0] == "voix-de-l-operateur"


def test_manifeste_illisible_ne_casse_pas_le_chargement(sans_manifestes):
    (sans_manifestes / "casse.json").write_text("{ ceci n'est pas du json",
                                                encoding="utf-8")
    (sans_manifestes / "bon.json").write_text(json.dumps({
        "service": "radio", "profils": {"radio": {"voix": "animateur"}},
    }), encoding="utf-8")
    p = Profils({"voix_defaut": "lexie-fr"})
    assert p.resoud("radio")[0] == "animateur"
