# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3324 : le mode hors ligne du menu dit la vraie cause, en français, et réessaie seul."""
from pathlib import Path

JS = (Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")
BLOC = JS[JS.index("var dernierStatutMenu = 0;"):JS.index("// HELPERS")]


def test_plus_de_mode_offline_anglais_ni_bouton_retry():
    assert "OFFLINE MODE" not in BLOC and "API unavailable" not in BLOC and "Retry" not in BLOC


def test_causes_distinguees():
    for mot in ("Session expirée", "Réservé à l'administration locale", "Module arrêté", "Box injoignable"):
        assert mot in BLOC, mot
    assert "/login.html" in BLOC                       # « Se reconnecter » (sur admin.<box> : renvoi vers le maître)


def test_nouvel_essai_automatique_30_puis_60_s():
    assert "30000" in BLOC and "60000" in BLOC and "forceReinject" in BLOC


def test_lien_vers_les_modules_de_la_box_legere():
    assert "/pilotage-connexion/modules.html" in BLOC


def test_le_statut_du_menu_est_retenu():
    assert "dernierStatutMenu = result.status" in JS
