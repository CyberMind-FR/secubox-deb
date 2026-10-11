# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2358 — le SOC rassemble les vues WAF, DPI et Actor Intelligence : une seule source, encadrées de même origine."""
import pathlib
import re

P = pathlib.Path(__file__).resolve().parents[2]
SOC = (P / "secubox-soc/www/soc/index.html").read_text(encoding="utf-8")
VUES = {"menaces": "/waf/menaces.html", "attaquants": "/waf/attaquants.html", "campagnes": "/waf/campagnes.html",
        "surfaces": "/waf/surfaces.html", "visites": "/waf/visites.html", "historique": "/waf/historique.html",
        "trafic": "/dpi/vue.html", "renseignement": "/actor-intelligence/"}


def test_chaque_vue_est_un_onglet_de_meme_origine():
    urls = re.findall(r'data-vue="([^"]+)"', SOC)
    assert len(urls) == len(VUES)
    for u in VUES.values():
        assert any(x.startswith(u) for x in urls), u
    assert all(x.startswith("/") and not x.startswith("//") for x in urls)   # jamais une autre origine


def test_les_onglets_existants_sont_conserves():
    for t in ("t0", "t1", "t2", "t3"):
        assert f'id="{t}"' in SOC


def test_le_gestionnaire_ne_laisse_qu_un_ecran_visible():
    assert "e.hidden = e.id !== cible" in SOC          # plusieurs onglets pilotent le même écran
    assert "sbxWafVue || e.data.sbxdpiVue" in SOC


def test_les_pages_dpi_et_waf_mesurent_leur_cadre():
    for f in ("secubox-dpi/www/dpi/vue.html",):
        t = (P / f).read_text(encoding="utf-8")
        assert "documentElement.scrollHeight" not in t and "container-name:a;min-height:100vh" not in t
