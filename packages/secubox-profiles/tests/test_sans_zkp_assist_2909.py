# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2909 — zkp et assistance ne font partie d'aucun profil."""
import re
import tomllib
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
PROFILS = sorted((PAQUETS / "secubox-profiles" / "profiles").glob("*.toml"))
METAS = ["secubox-full", "secubox-lite", "secubox-meta", "secubox-profils"]


def test_aucun_profil_n_allume_zkp_et_tous_masquent_les_deux_entrees():
    assert PROFILS
    for p in PROFILS:
        d = tomllib.loads(p.read_text())
        assert "zkp" not in d["on"], p.name
        assert {"zkp", "assist"} <= set(d.get("menu_off", [])), p.name


def test_aucun_meta_paquet_ne_depend_ni_ne_suggere_zkp_ou_assist():
    for m in METAS:
        ctrl = (PAQUETS / m / "debian" / "control").read_text()
        assert not re.search(r"secubox-(zkp|assist)\b", ctrl), m
