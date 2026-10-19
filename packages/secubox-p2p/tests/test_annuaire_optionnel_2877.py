# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2877 — secubox-p2p est ÉMANCIPÉ de secubox-annuaire : il ne l'exige plus (Recommends). Son client parle à l'annuaire par la socket et « ne lève jamais » (donnée, erreur)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def _champ(nom):
    ctl = re.sub(r"(?m)^#.*\n", "", (PKG / "debian" / "control").read_text(encoding="utf-8"))
    m = re.search(rf"(?m)^{nom}:((?:.*\n)(?: .*\n)*)", ctl)
    return m.group(1) if m else ""


def test_p2p_n_exige_plus_annuaire():
    assert "secubox-annuaire" not in _champ("Depends")
    assert "secubox-annuaire" in _champ("Recommends")


def test_le_client_de_l_annuaire_ne_leve_jamais_quand_il_est_absent():
    import importlib.util
    spec = importlib.util.spec_from_file_location("annuaire_client_2877", PKG / "api" / "annuaire_client.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ANNUAIRE_SOCK = "/nonexistent/annuaire.sock"
    data, err = m.get_catalog()
    assert err and not data
