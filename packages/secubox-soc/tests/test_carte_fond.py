# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Panneau SOC : la carte des origines a un vrai fond (continents en points), pas seulement un quadrillage."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "soc" / "index.html").read_text()


def test_la_carte_a_un_fond_de_continents():
    assert 'id="carte-terre"' in HTML, "groupe SVG du fond de carte"
    assert "function fondDeCarte(" in HTML and "fondDeCarte();" in HTML
    assert re.search(r'var TERRE\s*=\s*"[01][0-9,|01]+"', HTML), "fond embarqué (Natural Earth, domaine public)"


def test_le_fond_suit_la_projection_des_bulles():
    # même fenêtre que projette() : lon −130…130, lat 65…−5, 740 × 200
    assert "(lon + 130) / 260 * 740" in HTML and "(65 - lat) / 70 * 200" in HTML
    assert "-130" in HTML and "lat < -5" in HTML


def test_les_pays_manquants_sont_places():
    for iso in ("AU", "ZA", "MX", "AR", "EG"):
        assert re.search(rf"\b{iso}:\[", HTML), iso


def test_aucune_ressource_externe():
    assert "http://" not in HTML.replace("http://www.w3.org/2000/svg", "")
