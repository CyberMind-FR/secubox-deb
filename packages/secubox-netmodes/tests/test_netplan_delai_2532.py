# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2532 — `netplan apply` de secubox-net-detect : 5 s tuaient l'application en cours sur une RPi (« skipped or failed » au premier boot)."""
import re
from pathlib import Path

TEXTE = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-net-detect").read_text()


def test_netplan_apply_a_le_temps_de_finir():
    m = re.search(r"timeout (\d+) netplan apply", TEXTE)
    assert m and int(m.group(1)) >= 30


def test_l_echec_dit_pourquoi():
    ligne = next(l for l in TEXTE.splitlines() if "netplan apply" in l and "timeout" in l)
    assert "log " in ligne and "$?" in ligne or "code" in ligne
