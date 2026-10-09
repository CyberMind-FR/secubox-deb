# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2050 — vague 0 du plan de simplification : des dépendances qui désignaient un paquet inexistant ou manquaient."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def _champ(paquet, champ):
    t = (RACINE / "packages" / paquet / "debian" / "control").read_text()
    m = re.search(rf"(?ms)^{champ}:(.*?)(?=^\S)", t + "\nZ")
    return m.group(1) if m else ""


def _binaires():
    noms = set()
    for c in RACINE.glob("packages/*/debian/control"):
        noms.update(re.findall(r"(?m)^Package:\s*(\S+)", c.read_text()))
    return noms


def test_streamforge_est_retire_et_le_vrai_nom_du_paquet_streamlit_existe():
    """streamforge est un composant de streamlit depuis #2050 ; son transitoire est retiré. Le vrai nom est « secubox-streamlit » (« streamlit » seul n'existe pas)."""
    assert not (RACINE / "packages" / "secubox-streamforge").exists()
    assert "secubox-streamlit" in _binaires() and "streamlit" not in _binaires()


def test_zkp_recommande_les_outils_dont_il_appelle_les_binaires():
    # secubox-zkp appelle zkp_keygen / zkp_prover / zkp_verifier (api/main.py) ; il dégrade proprement s'ils manquent
    # (`which`), donc Recommends et non Depends : les outils ne sont pas publiés pour toutes les architectures.
    assert "zkp-hamiltonian-tools" in _champ("secubox-zkp", "Recommends")
    assert "zkp-hamiltonian-tools" in _binaires()
