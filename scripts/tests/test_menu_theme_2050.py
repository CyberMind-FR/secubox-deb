# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 vague 1 : chaque entrée menu.d porte un `theme` dérivé de arbre.yaml (test de dérive)."""
import importlib.util
import json
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
_s = importlib.util.spec_from_file_location("gen_theme", RACINE / "scripts/generate-menu-theme.py")
gen = importlib.util.module_from_spec(_s)
_s.loader.exec_module(gen)


def test_themes_connus_et_stables():
    t = gen.theme_par_paquet()
    assert t["secubox-qos"] == "reseau"
    assert t["secubox-hub"] == "hall"
    assert t["secubox-voicestudio"] == "assistant"
    assert set(t.values()) >= {"socle", "reseau", "bouclier", "media", "nuage", "hall"}


def test_aucune_derive_entre_menu_d_et_l_arbre():
    ecarts = gen.ecarts()
    assert not ecarts, "relancer scripts/generate-menu-theme.py : " + ", ".join(ecarts[:10])


def test_chaque_menu_a_un_theme_et_reste_du_json_valide():
    for f in RACINE.glob("packages/*/menu.d/*.json"):
        d = json.loads(f.read_text())
        assert d.get("theme"), f"{f} sans theme"


def test_un_paquet_hors_arbre_est_signale_pas_ignore():
    assert gen.theme_de("secubox-inconnu-xyz", {}) is None
