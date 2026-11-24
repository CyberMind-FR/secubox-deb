# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Repères partagés des cartes de campagne (#3919) : copie identique dans deux paquets, logique testée sous node."""
import shutil
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
WAF = RACINE / "packages/secubox-waf-ng/www/actor/reperes.js"
IA = RACINE / "packages/secubox-ai/www/ai/reperes.js"
TEST_MJS = Path(__file__).with_name("reperes_3919.test.mjs")


def test_copies_identiques():
    assert WAF.read_bytes() == IA.read_bytes()


def test_installation_dans_les_rules():
    for paquet, page in (("secubox-waf-ng", "actor"), ("secubox-ai", "ai")):
        rules = (RACINE / f"packages/{paquet}/debian/rules").read_text(encoding="utf-8")
        assert f"www/{page}/reperes.js" in rules


def test_reperes_node():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", "--test", str(TEST_MJS)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
