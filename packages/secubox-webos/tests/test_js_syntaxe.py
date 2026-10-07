# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Chaque script en ligne du Hall et de ses cartes est du JavaScript valide.

Incident : une apostrophe non échappée dans une chaîne (« jusqu'à ») cassait tout le script de la carte Actor alors que les tests de contenu
passaient. `node --check` attrape ce que `assert "..." in HTML` ne voit pas.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

HALL = Path(__file__).resolve().parents[1] / "www" / "hall"
PAGES = sorted([HALL / "index.html", *(HALL / "cardlets").glob("*.html")])
SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*type=[\"'](?!text/javascript|module)[^\"']*[\"'])[^>]*>(.*?)</script>", re.S | re.I)

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node absent")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_les_scripts_en_ligne_sont_valides(page):
    scripts = SCRIPT.findall(page.read_text())
    for i, js in enumerate(scripts):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
        r = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
        assert r.returncode == 0, f"{page.name}, script {i + 1} : {r.stderr.strip().splitlines()[-1] if r.stderr else 'erreur'}"
