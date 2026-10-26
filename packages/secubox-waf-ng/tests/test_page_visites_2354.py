# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page autonome de l'onglet Visites du WAF (#2354) : contrat statique, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants/waf/www/waf/visites.html"


def _src() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_spdx_cmsd():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in _src()[:400]


def test_hauteur_auto_et_demo():
    s = _src()
    assert "sbxWafVue" in s and "onglet:'visites'" in s
    assert "ResizeObserver" in s
    assert "'demo'" in s
    assert "DONNÉES DE DÉMONSTRATION" in s


def test_cadre_sans_min_height_viewport():
    assert "min-height:100vh" not in _src()


def test_route_api_et_actualisation():
    s = _src()
    assert "/api/v1/waf/visits" in s
    assert "30000" in s


def test_aucun_script_externe():
    assert not re.search(r"<script[^>]+src=", _src(), re.I)
    assert not re.search(r"https?://", re.sub(r"https?://www\.w3\.org\S*", "", _src()))


def test_pas_de_lorem_ni_secret():
    s = _src().lower()
    for mot in ("lorem", "password", "passwd", "secret", "api_key", "apikey", "bearer ey"):
        assert mot not in s, mot


def test_la_note_dit_ou_l_agent_utilisateur_brut_est_conserve_3176():
    """#3176 : « l'agent utilisateur brut n'est jamais stocké » était vrai pour ces statistiques, pas pour la box : les journaux d'accès de nginx
    (14 jours) et le journal des menaces du WAF (7 jours) le gardent. La note le dit."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf" / "visites.html").read_text(encoding="utf-8")
    assert "jamais stocké" not in html
    note = html[html.index("Seules des statistiques agrégées"):].split("</div>")[0]
    assert "nginx" in note and "14 jours" in note and "journal des menaces" in note and "7 jours" in note


def test_la_tuile_menaces_24h_annonce_une_fenetre_glissante_3176():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf" / "index.html").read_text(encoding="utf-8")
    tuile = html[html.index('<span class="l">Menaces 24 h</span>') - 400:html.index('<span class="l">Menaces 24 h</span>')]
    assert "24 dernières heures" in tuile
