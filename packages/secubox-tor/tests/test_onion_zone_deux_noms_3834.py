# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3834 : le diagnostic .onion reconnaît la zone sous ses deux noms valides."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("tormain", Path(__file__).resolve().parents[1] / "api" / "main.py")


def _noms():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    return src


def test_les_deux_noms_sont_reconnus():
    src = _noms()
    assert "secubox-onion-forward.conf" in src, "nom posé par torctl absent du diagnostic"
    assert "48-secubox-onion.conf" in src, "nom posé par la toolbox absent du diagnostic"
    assert "any(z.exists() for z in ONION_FORWARD_ZONES)" in src
