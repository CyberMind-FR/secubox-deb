# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3922 : une place par panneau. Le WAF garde le détail, le SOC en donne la synthèse : plus d'onglets WAF dans /soc/,
Guardian ne recalcule plus les cinq panneaux du WAF et les remplace par une bande « Pare-feu applicatif » qui y renvoie."""
import re
from pathlib import Path

WWW = Path(__file__).resolve().parents[1] / "www" / "soc"
INDEX = (WWW / "index.html").read_text(encoding="utf-8")
GUARDIAN = (WWW / "guardian.html").read_text(encoding="utf-8")


def test_index_n_encadre_plus_aucune_page_du_waf():
    assert 'data-vue="/waf/' not in INDEX
    for page in ("menaces", "attaquants", "campagnes", "surfaces", "visites", "historique"):
        assert f"/waf/{page}.html" not in INDEX


def test_index_a_un_lien_de_premier_niveau_vers_le_waf():
    m = re.search(r'<a [^>]*href="/waf/"[^>]*>(.*?)</a>', INDEX, re.S)
    assert m and "Détail dans le WAF" in m.group(1)
    assert 'target="_top"' in m.group(0) and "data-vue" not in m.group(0)


def test_les_autres_onglets_restent_et_le_defaut_est_guardian():
    for t in ("tdef", "t0", "tn", "td", "tr", "t1", "t2", "t3"):
        assert f'id="{t}"' in INDEX, t
    assert re.search(r'id="t0"', INDEX) and 'aria-selected="true" aria-controls="e0" id="t0"' in INDEX


def test_aucune_reference_aux_onglets_retires_dans_le_script():
    script = INDEX[INDEX.index("<script"):]
    for ident in ("tm", "ta", "tc", "ts", "tv", "th"):
        assert f'id="{ident}"' not in INDEX, ident
        assert not re.search(rf"""["'#]{ident}["']|getElementById\(["']{ident}["']\)|\$\(["']{ident}["']\)""", script), ident
    # le lien n'est pas un onglet : le gestionnaire de clic ne le prend pas
    assert '.onglet:not(.lien)' in script


def test_guardian_ne_recopie_plus_les_panneaux_du_waf():
    for titre in ("Carte des attaques", "Ce qui protège", "Derniers événements détectés", "Répartition par catégorie", "Évolution des événements"):
        assert titre not in GUARDIAN, titre
    for mort in ("function monde(", "function courbe(", "function croise(", "id=\"donut\"", "id=\"legT\"", "id=\"events\"", "alerts?limit", "/detections"):
        assert mort not in GUARDIAN, mort


def test_guardian_garde_ce_qui_lui_est_propre():
    for titre in ("Applications / usages", "Appareils principaux", "Canaris / leurres", "État du mode Guardian", "Filtrage web"):
        assert titre in GUARDIAN, titre


def test_guardian_a_la_bande_pare_feu_applicatif_qui_renvoie_au_waf():
    assert "Pare-feu applicatif" in GUARDIAN and 'id="pareFeu"' in GUARDIAN
    assert re.search(r'<a href="/waf/" target="_top">Détail dans le WAF', GUARDIAN)
    liens = set(re.findall(r"case_\('(/waf/[a-z]+\.html)'", GUARDIAN))
    assert {"/waf/menaces.html", "/waf/vue.html", "/waf/historique.html"} <= liens
    assert GUARDIAN.count('target="_top"') >= 2 and "const " not in GUARDIAN.split("<script>")[1]
