# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page /ai/ de secubox-ai (#3583, tâche 14) : onglets, retraits de l'étape 1, noms de fonctions uniques, syntaxe JS."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from api.main import app

PAGE = Path(__file__).resolve().parents[1] / "www" / "ai" / "index.html"
ONGLETS_ATTENDUS = ["essai", "menaces", "code", "documents", "memoire", "historique", "modeles", "prefs", "medias", "journal"]


@pytest.fixture(scope="module")
def html():
    return PAGE.read_text(encoding="utf-8")


def script(html):
    blocs = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(blocs) == 1
    return blocs[0]


def test_onglets_exacts(html):
    declares = re.search(r"var ONGLETS\s*=\s*\[(.*?)\];", html, re.S).group(1)
    assert re.findall(r"\['([a-z]+)',\s*'[^']+'\]", declares) == ONGLETS_ATTENDUS
    assert re.findall(r'<section data-o="([a-z]+)"', html) == ONGLETS_ATTENDUS


def test_aucune_reference_retiree(html):
    for interdit in ("/obliteratus", "/image", "/animation", "/agents", "/generateur", "/voix"):
        assert interdit not in html, interdit
    for mot in ("OBLITERATUS", "Écouter", "Générateur", "data-ecoute"):
        assert mot not in html, mot


def test_pattern_12_sidebar(html):
    assert '<script src="/shared/sidebar.js"></script>' in html
    assert re.search(r'<nav class="sidebar"', html)
    assert "sbx_token" in html


def test_tuile_moteur_et_boutons(html):
    assert 'id="tMoteur"' in html and "'/status'" in html
    for libelle in ("■ Local", "■ Distant", "Auto"):
        assert libelle in html
    assert "'/moteur/' + choix" in html


def test_fonctions_declarees_une_seule_fois(html):
    noms = re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", script(html))
    doublons = sorted({n for n in noms if noms.count(n) > 1})
    assert noms and not doublons, doublons


def test_pas_d_innerhtml(html):
    assert "innerHTML" not in script(html) and "insertAdjacentHTML" not in script(html)


def test_script_passe_node_check(html, tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    f = tmp_path / "page.js"
    f.write_text(script(html), encoding="utf-8")
    r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_la_page_n_appelle_que_des_routes_existantes(html):
    """Premier segment de chaque appel `API + '/…'` : il doit exister dans l'application."""
    existants = {r.path.split("/")[1] for r in app.routes if getattr(r, "path", "").count("/") >= 1 and r.path != "/"}
    appeles = set(re.findall(r"API \+ '/([a-z-]+)", script(html)))
    assert appeles
    assert not appeles - existants, appeles - existants


# ---- revue finale : session expirée distinguée d'un module injoignable ----
def _fonction(source, nom):
    debut = source.index(f"function {nom}(")
    profondeur, i = 0, source.index("{", debut)
    while True:
        profondeur += {"{": 1, "}": -1}.get(source[i], 0)
        if profondeur == 0:
            return source[debut:i + 1]
        i += 1


@pytest.mark.parametrize("code", [401, 403])
def test_session_expiree_et_non_module_injoignable(html, tmp_path, code):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    f = tmp_path / "t.js"
    f.write_text(_fonction(script(html), "lireReponse") + f"""
lireReponse({{ ok: false, status: {code}, json: function () {{ return Promise.resolve({{ detail: 'Not authenticated' }}); }} }})
  .then(function () {{ process.exit(3); }}, function (e) {{ console.log(e.status + '|' + e.message); }});
""", encoding="utf-8")
    r = subprocess.run([node, str(f)], capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == f"{code}|Session expirée : reconnectez-vous", r.stdout + r.stderr


def test_bandeau_d_etat_session_expiree(html):
    corps = _fonction(script(html), "chargerEtat")
    assert "e.status === 401 || e.status === 403" in corps and "Session expirée : reconnectez-vous" in corps
