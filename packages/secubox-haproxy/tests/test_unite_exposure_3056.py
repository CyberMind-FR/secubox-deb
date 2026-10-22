# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3056 — l'unité du composant exposure, installée par debian/rules (hors dh_installsystemd), doit être activée par le
postinst et arrêtée par le prerm : sur gk2 elle n'avait jamais démarré (page Exposition « HORS LIGNE », API 404)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_le_postinst_active_l_unite_du_composant_exposure():
    postinst = (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert re.search(r"systemctl enable --now secubox-exposure\.service", postinst)


def test_le_prerm_arrete_l_unite_du_composant_exposure():
    prerm = (PKG / "debian" / "prerm").read_text(encoding="utf-8")
    assert "systemctl stop    secubox-exposure.service" in prerm


def test_l_unite_est_bien_installee_par_rules():
    rules = (PKG / "debian" / "rules").read_text(encoding="utf-8")
    assert "composants/exposure/debian/secubox-exposure.service" in rules
