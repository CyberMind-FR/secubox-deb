# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Webui network-anomaly au profil Aurora (#2380) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants/network-anomaly/www/network-anomaly/index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_hauteur_et_demo():
    assert "sbxVue" in SRC and "onglet:'network-anomaly'" in SRC
    assert "demo" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "min-height:100vh" not in SRC.replace(" ", "")
    assert "documentElement.scrollHeight" not in SRC


def test_aucune_dependance_externe():
    assert not re.search(r"<script[^>]+src=", SRC)                      # le menu est chargé par le script de la page, depuis /shared/ (local)
    assert "fonts.googleapis" not in SRC
    assert re.findall(r"<link[^>]+>", SRC) == ['<link rel="stylesheet" href="/shared/sidebar-light.css">']   # seule feuille : celle du menu de la box


def test_pas_de_lorem_ni_secret():
    low = SRC.lower()
    assert "lorem" not in low
    for m in ("password", "secret", "private key"):
        assert m not in low


def test_pas_de_dialogues_navigateur():
    for f in ("confirm(", "alert(", "prompt("):
        assert f not in SRC


def test_routes_lues():
    for r in ("/api/v1/network-anomaly", "/alerts?hours=24", "/stats", "/baselines"):
        assert r in SRC


def test_ecriture_identique_et_inerte_en_demo():
    # même appel que l'ancienne page : POST /alerts/{id}/acknowledge, jeton Bearer, JSON
    assert "'/alerts/'+encodeURIComponent(id)+'/acknowledge'" in SRC
    assert "method:'POST'" in SRC
    assert "'Content-Type'" in SRC and "Authorization" in SRC and "sbx_token" in SRC
    assert "if(S.demo)" in SRC
    assert SRC.count("method:'POST'") == 1          # aucune action inventée
    assert "/block" not in SRC                       # route inexistante côté API : non reprise


def test_mesure_absente_en_tiret_et_actualisation():
    assert "'—'" in SRC and "setInterval" in SRC and "30000" in SRC and "document.hidden" in SRC


def test_menu_de_gauche_present_hors_cadre_et_demo_2463():
    """Sans la barre laterale et /shared/sidebar.js, la page n'avait plus de menu à gauche."""
    assert '<nav class="sidebar" id="sidebar"></nav>' in SRC and '<main class="principal">' in SRC and "</main>" in SRC
    assert SRC.index('<main class="principal">') < SRC.index('<div class="cadre">') < SRC.index("</main>")        # le cadre est DANS le contenu décalé
    assert "body:not(.emb) .principal{margin-left:220px" in SRC and "body.emb #sidebar,body.demoOn #sidebar{display:none}" in SRC
    assert re.search(r"if\(!q\.get\('embed'\)&&!DEMO_ON\)\{.*?/shared/sidebar\.js", SRC)       # ni en cadre ni en démonstration
