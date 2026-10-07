# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page « Évolution et efficacité » du WAF : carte du monde, badge d'état honnête, efficacité repliée."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "waf" / "tableau.html").read_text()


def test_le_badge_ne_dit_plus_en_ecoute_en_dur():
    # « en écoute » laisse croire à un mode passif alors que le WAF écarte et bannit : le badge dit l'état réel
    assert "en écoute" not in HTML
    assert 'id="live"' in HTML and "function etatMoteur(" in HTML
    for mot in ("actif", "injoignable"):
        assert mot in HTML


def test_une_carte_du_monde_montre_d_ou_viennent_les_attaques():
    assert 'id="carteMonde"' in HTML and 'id="paysTop"' in HTML
    assert "function carteMonde(" in HTML and "top_ips_countries" in HTML


def test_l_efficacite_par_categorie_est_repliee_avec_une_synthese():
    m = re.search(r"<details[^>]*id=\"efficaciteDetails\"[^>]*>", HTML)
    assert m and " open" not in m.group(0), "repliée par défaut"
    assert 'id="efficaciteResume"' in HTML and 'id="efficacite"' in HTML


def test_pas_de_ressource_externe():
    assert "http://" not in HTML.replace("http://www.w3.org/2000/svg", "")
