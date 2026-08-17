# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metablogizer — supprimer un site ne condamne pas les autres (#1041)

CyberMind — https://cybermind.fr

CE QUE CE TEST GARDE. `force_remove` faisait `os.chmod(parent, 0o700)` pour
débloquer une suppression. Ce parent est PARTAGÉ par tous les sites : il perdait
ses bits groupe et autres, `www-data` ne pouvait plus le traverser, et les 174
autres sites tombaient en 500.

LE DÉFAUT NE SE SIGNALAIT PAS : la suppression réussissait. La panne
n'apparaissait qu'au prochain accès à un site voisin — ailleurs, plus tard, sans
lien apparent avec l'action qui l'avait causée.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rmtree import force_remove


def test_le_parent_partage_reste_traversable(tmp_path):
    """LE CŒUR DU DÉFAUT : le parent garde ses bits pour autrui."""
    parent = tmp_path / "sites"
    parent.mkdir(mode=0o755)
    voisin = parent / "site-voisin"
    voisin.mkdir()
    (voisin / "index.html").write_text("je dois rester servi")

    cible = parent / "site-a-supprimer"
    cible.mkdir()
    (cible / "index.html").write_text("x")
    # 0o000 ET NON 0o500. En 0o500 la suppression aboutit sans jamais echouer,
    # donc le chemin fautif n'est pas emprunte et le test passe meme avec le
    # bogue — une garde qui ne garde rien. Il faut rendre le repertoire
    # ILLISIBLE pour declencher le rattrapage.
    os.chmod(cible, 0o000)

    force_remove(cible)

    assert not cible.exists(), "le site visé aurait dû disparaître"
    mode = os.stat(parent).st_mode & 0o777
    assert mode & 0o055, (
        f"le parent partagé est retombé en {oct(mode)} : les autres sites "
        "ne seraient plus servis")
    assert (voisin / "index.html").read_text() == "je dois rester servi"


def test_les_bits_du_proprietaire_sont_bien_ajoutes(tmp_path):
    """On AJOUTE ce qui manque — sans quoi la suppression échouerait."""
    parent = tmp_path / "sites"
    parent.mkdir(mode=0o755)
    cible = parent / "site"
    cible.mkdir()
    (cible / "f").write_text("x")
    os.chmod(cible, 0o000)

    force_remove(cible)
    assert not cible.exists()
