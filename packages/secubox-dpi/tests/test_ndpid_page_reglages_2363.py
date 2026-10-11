# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page « Réglages » de nDPId (profil Aurora) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent / "composants" / "ndpid" / "www" / "ndpid"
PAGE = (RACINE / "reglages.html").read_text(encoding="utf-8")
ANCIEN = (RACINE / "index.html").read_text(encoding="utf-8")


def test_spdx_et_marqueurs():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE
    for m in ("sbxNdpidVue", "demo", "embed", "onglet:'reglages'", "container-type:inline-size"):
        assert m in PAGE
    assert "min-height:100vh" not in PAGE


def test_aucune_ressource_externe_ni_secret():
    assert not re.search(r"<script[^>]+src=", PAGE)
    assert not re.search(r"https?://", re.sub(r"http://www\.w3\.org", "", PAGE))
    assert "lorem" not in PAGE.lower()
    assert not re.search(r"(password|secret|api[_-]?key)\s*[:=]", PAGE, re.I)
    assert "confirm(" not in PAGE and "alert(" not in PAGE


def test_routes_ecriture_identiques_a_l_ancienne_page():
    assert "const API_BASE = '/api/v1/ndpid'" in ANCIEN and "API_BASE='/api/v1/ndpid'" in PAGE
    # l'ancienne page écrit via POST sur ces seules routes
    anciennes = set(re.findall(r"apiFetch\(`(/[^`$]+?)(?:\$\{action\})?`, \{ method: 'POST' \}", ANCIEN))
    assert "/mirred/setup" in anciennes and "/mirred/remove" in anciennes
    assert "/control/${action}" in ANCIEN
    for action in ("start", "restart", "stop"):
        assert f"chemin:'/control/{action}'" in PAGE
    for r in ("/mirred/setup", "/mirred/remove"):
        assert f"chemin:'{r}'" in PAGE
    assert "method:'POST'" in PAGE and "'Authorization':'Bearer '+t" in PAGE
    assert "localStorage.getItem('sbx_token')" in PAGE and "credentials:'same-origin'" in PAGE
    # aucune route d'écriture inventée
    assert len(re.findall(r"method:'POST'", PAGE)) == 1
    assert "/settings'" not in re.sub(r"jget\('/settings'\)", "", PAGE)


def test_lectures_et_demo_inerte():
    for r in ("/status", "/settings", "/mirred/status", "/stats/realtime"):
        assert f"jget('{r}')" in PAGE
    # en démonstration, l'écriture n'est jamais appelée
    assert re.search(r"if\(DEMO_ON\)\{resultat\([^}]*return;\}\s*btns", PAGE)
