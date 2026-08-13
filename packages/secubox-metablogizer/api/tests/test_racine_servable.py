# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Rattrapage d'un contenu depose un cran trop bas (#1023)."""
from pathlib import Path

from main import racine_servable


def test_index_a_la_racine_rien_ne_bouge(tmp_path):
    (tmp_path / "index.html").write_text("x")
    (tmp_path / "sous").mkdir()
    (tmp_path / "sous" / "index.html").write_text("y")
    assert racine_servable(tmp_path) == (str(tmp_path), None)


def test_contenu_un_cran_plus_bas_est_servi(tmp_path):
    # Le cas exact de `www` : l'archive `gk2net.zip` deballee avant le correctif.
    sous = tmp_path / "gk2net"
    sous.mkdir()
    (sous / "index.html").write_text("x")
    (sous / "assets").mkdir()
    assert racine_servable(tmp_path) == (str(sous), "gk2net")


def test_deux_sous_dossiers_on_ne_choisit_pas(tmp_path):
    # Descendre reviendrait a tirer au sort lequel des deux EST le site.
    for n in ("a", "b"):
        (tmp_path / n).mkdir()
        (tmp_path / n / "index.html").write_text("x")
    assert racine_servable(tmp_path) == (str(tmp_path), None)


def test_un_fichier_a_la_racine_empeche_la_descente(tmp_path):
    # Un `robots.txt` a la racine dit que la racine EST le site, meme sans index.
    (tmp_path / "robots.txt").write_text("x")
    sous = tmp_path / "site"; sous.mkdir()
    (sous / "index.html").write_text("y")
    assert racine_servable(tmp_path) == (str(tmp_path), None)


def test_sous_dossier_sans_index_ne_compte_pas(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a.css").write_text("x")
    assert racine_servable(tmp_path) == (str(tmp_path), None)


def test_dossier_inexistant_ne_leve_pas(tmp_path):
    absent = tmp_path / "jamais"
    assert racine_servable(absent) == (str(absent), None)
