# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2354 — l'administration du WAF porte le profil projet référence Aurora sur tous ses onglets."""
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parents[1] / "composants/waf/www/waf/index.html"
S = PAGE.read_text(encoding="utf-8")


def test_le_profil_aurora_est_present_et_remappe_la_palette():
    assert "PROFIL PROJET RÉFÉRENCE AURORA" in S
    bloc = S[S.index("PROFIL PROJET RÉFÉRENCE AURORA"):]
    for jeton in ("--fond: #060d1b", "--cyan: #29b6f6", "--red: #ff4d5e", "--green: #2ecc71"):
        assert jeton in bloc


def test_les_six_autres_onglets_sont_couverts_par_les_memes_classes():
    for onglet in ("overview", "attackers", "visits", "recon", "history", "campaigns"):
        assert f'data-tab="{onglet}"' in S
    bloc = S[S.index("PROFIL PROJET RÉFÉRENCE AURORA"):]
    for classe in (".card", ".stat-card", ".data-table", ".waf-tab", ".btn"):
        assert re.search(re.escape(classe) + r"[\s,{.:]", bloc), classe


def test_aurora_repond_au_skin_partage_a_specificite_superieure():
    """hybrid-skin.css est injecté après la page et pose ses teintes en !important : sans préfixe plus spécifique, rien ne change."""
    bloc = S[S.index("PROFIL PROJET RÉFÉRENCE AURORA"):]
    assert "html :is(.hybrid-skin, body) button.waf-tab" in bloc
    assert "html :is(.hybrid-skin, body) .stat-card .value" in bloc
    assert "html :is(.hybrid-skin, body) table th" in bloc
