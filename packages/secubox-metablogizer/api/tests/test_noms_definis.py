# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metablogizer — aucun nom indéfini dans le module (#1033)

CyberMind — https://cybermind.fr

CE QUE CE TEST GARDE, ET POURQUOI IL EXISTE. `_version_upload()` appelait
`asyncio.get_running_loop()` alors qu'`asyncio` n'était importé nulle part dans
sa portée : l'import local de son APPELANTE ne descend pas dans l'appelée. Le
défaut ne se voyait ni à l'import du module, ni au démarrage, ni aux tests —
seulement au premier envoi de contenu, en production, sous la forme d'un 500.

ET IL MENTAIT SUR CE QU'IL AVAIT FAIT : l'appel arrivant APRÈS l'extraction de
l'archive, le contenu était bien écrit, mais l'opérateur lisait « échec » et
recommençait. Un échec annoncé sur un travail accompli est pire qu'un échec
franc — on refait ce qui est déjà fait.

Ce test ne vérifie donc pas l'import d'`asyncio` : il vérifie qu'AUCUN nom du
module n'est indéfini. Corriger l'instance sans poser cette garde laisserait la
prochaine passer par le même chemin.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

API = Path(__file__).resolve().parent.parent
SOURCES = sorted(API.glob("*.py")) + sorted((API / "routers").glob("*.py"))


def test_aucun_nom_indefini():
    pyflakes = pytest.importorskip(
        "pyflakes",
        reason="pyflakes absent : la garde ne peut pas s'exercer",
    )
    assert pyflakes  # l'import est la seule chose qu'on lui demande

    r = subprocess.run(
        [sys.executable, "-m", "pyflakes", *map(str, SOURCES)],
        capture_output=True, text=True,
    )
    # `pyflakes` rend tout sur la sortie standard, un défaut par ligne. On ne
    # retient QUE les noms indéfinis : les imports inutilisés sont du désordre,
    # pas une panne, et faire échouer là-dessus rendrait la garde bruyante donc
    # rapidement contournée.
    fautes = [l for l in r.stdout.splitlines() if "undefined name" in l]
    assert not fautes, "noms indéfinis :\n  " + "\n  ".join(fautes)
