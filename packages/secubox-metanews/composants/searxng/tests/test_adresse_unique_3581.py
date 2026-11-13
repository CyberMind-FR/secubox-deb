# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — l'adresse du conteneur sur br-lxc n'appartient à personne d'autre dans le dépôt (configurations, contrôleurs,
installateurs, routes, tests des autres modules). Un second conteneur sur la même adresse casserait les deux."""
import re
from pathlib import Path

from sbx_searxng import config as C

COMPOSANT = Path(__file__).resolve().parents[1]
RACINE = COMPOSANT.parents[3]
IGNORES = {".git", "node_modules", "vendor", "__pycache__", ".venv", "archive"}


def _fichiers():
    for base in ("packages", "common", "scripts", "image", "board", "docs", "tests"):
        d = RACINE / base
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if f.is_file() and not IGNORES & set(f.parts) and f.stat().st_size < 2_000_000:
                yield f


def test_adresse_du_conteneur_unique_dans_le_depot():
    ip = C.DEFAUTS["lxc"]["ip"]
    assert ip == "10.100.0.85" and ip != "10.100.0.80"
    motif = re.compile(re.escape(ip) + r"(?![0-9])")
    autres = []
    for f in _fichiers():
        if COMPOSANT in f.parents:
            continue
        try:
            texte = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if motif.search(texte) and "#3581" not in texte:
            autres.append(str(f.relative_to(RACINE)))
    assert autres == [], f"{ip} déjà utilisée ailleurs : {autres}"
