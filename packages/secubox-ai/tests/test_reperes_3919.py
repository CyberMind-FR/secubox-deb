# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Repères partagés des cartes de campagne (#3919) : copies identiques dans trois paquets, logique testée sous node."""
import shutil
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
WAF = RACINE / "packages/secubox-waf-ng/www/actor/reperes.js"
IA = RACINE / "packages/secubox-ai/www/ai/reperes.js"
PAGES_WAF = RACINE / "packages/secubox-waf-ng/composants/waf/www/waf"
PAGES_SOC = RACINE / "packages/secubox-soc/www/soc"
TEST_MJS = Path(__file__).with_name("reperes_3919.test.mjs")


def test_copies_identiques():
    for copie in (IA, PAGES_WAF / "reperes.js", PAGES_SOC / "reperes.js"):
        assert WAF.read_bytes() == copie.read_bytes(), copie


def test_cartes_partagees_waf_soc_identiques():
    assert (PAGES_WAF / "cartes-campagnes.js").read_bytes() == (PAGES_SOC / "cartes-campagnes.js").read_bytes()


def test_installation_dans_les_rules():
    for paquet, page in (("secubox-waf-ng", "actor"), ("secubox-ai", "ai")):
        rules = (RACINE / f"packages/{paquet}/debian/rules").read_text(encoding="utf-8")
        assert f"www/{page}/reperes.js" in rules
    # /waf/ et /soc/ : tout le dossier est copié, les deux scripts partent avec les pages
    waf = (RACINE / "packages/secubox-waf-ng/debian/rules").read_text(encoding="utf-8")
    assert "cp -r composants/waf/www/waf/. debian/secubox-waf-ng/usr/share/secubox/www/waf/" in waf
    soc = (RACINE / "packages/secubox-soc/debian/rules").read_text(encoding="utf-8")
    assert "cp -r www/soc/. debian/secubox-soc/usr/share/secubox/www/soc/" in soc


def test_reperes_node():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", "--test", str(TEST_MJS)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
