# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Téléchargement du rapport : lien direct d'abord, blob en repli seulement (Firefox, iframe du Hall)."""
from pathlib import Path

PAGE = (Path(__file__).parent.parent / "www" / "reporter" / "index.html").read_text()


def test_lien_direct_avant_le_blob():
    i_direct = PAGE.index("lanceTelechargement(url).remove()")
    i_blob = PAGE.index("URL.createObjectURL(blob)")
    assert i_direct < i_blob                              # le blob n'est qu'un repli


def test_revocation_du_blob_differee():
    assert "setTimeout(() => { URL.revokeObjectURL(href)" in PAGE
    assert "a.click();\n                URL.revokeObjectURL" not in PAGE   # avant : révoqué aussitôt


def test_ancre_dans_le_document():
    assert "document.body.appendChild(a)" in PAGE


def test_nom_de_fichier_sans_guillemet_final():
    assert 'filename="?([^";]+)"?' in PAGE                # l'ancien motif gardait le " final
