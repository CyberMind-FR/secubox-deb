# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3470 : le profil mobile ne ramène ni le Hall ni le WAF."""
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def test_mobile_repose_sur_minimal_qui_exclut_le_hall():
    assert "secubox-minimal" in (RACINE / "secubox-mobile/debian/control").read_text(encoding="utf-8")
    conflits = (RACINE / "secubox-minimal/debian/control").read_text(encoding="utf-8")
    assert "Conflicts: secubox-webos, secubox-waf-ng" in conflits


def test_la_cle_peut_rejoindre_le_maillage():
    control = (RACINE / "secubox-mobile/debian/control").read_text(encoding="utf-8")
    assert "secubox-p2p" in control and "secubox-annuaire" in control
