# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2354 — l'administration du WAF porte le profil projet référence Aurora sur tous ses onglets."""
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parents[1] / "composants/waf/www/waf/index.html"
S = PAGE.read_text(encoding="utf-8")


def test_le_profil_aurora_est_present_et_remappe_la_palette():
    """#2683 : la page porte les jetons Aurora nativement (plus de surcouche sur l'ancien skin)."""
    for jeton in ("--fond:#060d1b", "--cyan:#29b6f6", "--rouge:#ff4d5e", "--vert:#2ecc71"):
        assert jeton in S


def test_les_six_autres_onglets_sont_couverts_par_les_memes_classes():
    for onglet in ("overview", "attackers", "visits", "recon", "history", "campaigns"):
        assert f'data-tab="{onglet}"' in S
    for classe in (".pan", ".tuile", ".waf-tab", ".btn", "table"):
        assert re.search(re.escape(classe) + r"[\s,{.:]", S), classe


def test_aurora_ne_charge_plus_le_skin_partage():
    """#2683 : hybrid-skin.css (teintes en !important) n'est plus chargé, donc plus de surcharge à spécificité supérieure."""
    assert "hybrid-skin" not in S and "hybrid-dark" not in S
