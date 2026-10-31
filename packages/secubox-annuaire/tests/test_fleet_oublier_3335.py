# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3335 : bouton « Oublier » des pairs de la Flotte (nom retapé, seconde confirmation pour un nœud actif)."""
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "www" / "fleet" / "index.html").read_text(encoding="utf-8")


def test_bouton_oublier_et_routes():
    i = PAGE.index("function oublierNoeud(")
    bloc = PAGE[i:i + 3000]
    assert "/api/v1/p2p/master-link/oublier" in bloc and "/oublier'" in bloc and "/api/v1/pilotage/boxes/" in bloc
    assert "saisie.value !== nom" in bloc                                 # nom retapé, sinon rien n'est envoyé
    assert "forcer.checked" in bloc and "force: true" in bloc            # nœud encore en ligne : « forcer » coché
    assert "oublierNoeud(p.name, act, p.public_key)" in PAGE and "public_key: cle" in bloc and "<th>Dernier vu</th><th></th>" in PAGE


def test_le_bouton_n_est_pose_que_pour_un_nom_valide():
    assert "/^[a-z0-9][a-z0-9-]{0,62}$/.test(p.name)" in PAGE
