# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3302 — Flotte : bascule d'interface locale ⇄ distante depuis la page de la box (tests statiques du JS)."""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_fleet_box_3126_l2 import _injections, _js  # noqa: E402


def _actions():
    m = re.search(r"const PB_ACTIONS = \[(.*?)\];", _js(), re.S)
    assert m, "PB_ACTIONS introuvable"
    return m.group(1)


def test_les_deux_sens_sont_au_catalogue_avec_confirmation_forte():
    acts = _actions()
    for ident, sens in (("interface-distante", "locale"), ("interface-locale", "distante")):
        ligne = re.search(r"\{[^{}]*id: '" + ident + r"'[^{}]*\}", acts)
        assert ligne, ident
        assert "forte: true" in ligne.group(0), ident
        assert "si: '" + sens + "'" in ligne.group(0), ident     # proposée seulement depuis l'autre interface


def test_seul_le_sens_utile_est_propose_et_le_rendu_suit_l_interface():
    js = _js()
    assert re.search(r"PB_ACTIONS\.filter\(a => !a\.si \|\| a\.si === pbInterface\(b\)\)", js)
    assert re.search(r"const sig = \[[^\]]*b\.interface", js), "un changement d'interface doit refaire le catalogue"
    assert "function pbInterface(b)" in js


def test_page_toujours_saine():
    assert _injections(_js()) == []
