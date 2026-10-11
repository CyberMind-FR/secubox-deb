# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet Tor du Toolbox (#2373) : page statique, actions d'ecriture conservees."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "tor.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_contrat():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "sbxToolboxVue" in SRC and "onglet:'tor'" in SRC
    assert "demo" in SRC and "ResizeObserver" in SRC


def test_pas_de_externe_ni_dialogue_ni_secret():
    assert not re.search(r"<script[^>]+src=", SRC)
    assert not re.search(r"https?://[^\s'\"]*\.(js|css)", SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "lorem"):
        assert interdit not in SRC.lower().replace("ask(", "")
    assert not re.search(r"(?i)(private[_ ]?key|password|secret)", SRC)


def test_routes_lecture_et_ecriture():
    for r in ("/api/v1/toolbox", "/api/v1/nac", "/api/v1/tor", "/api/v1/exposure",
              "/admin/tor/state", "/exit_country", "/vpn/clients", "/tor/bridges",
              "/hidden_services", "/onion_dns"):
        assert r in SRC, r
    for r in ("'/admin/tor/'+(on?'on':'off')", "/admin/tor/newnym", "/admin/tor/check-leaks",
              "'/vpn/client'", "'/tor/bridge'", "/tor/emancipate_webui"):
        assert r in SRC, r
    assert "method:turnOn?'POST':'DELETE'" in SRC
    assert "method:'DELETE'" in SRC and "JSON.stringify({kind:kind,selector:selector})" in SRC
    assert "JSON.stringify({countries:liste})" in SRC
    assert "JSON.stringify({line:line})" in SRC
    assert "JSON.stringify({tor_preset:preset})" in SRC
    assert "'Authorization':'Bearer '+tok" in SRC and "sbx_token" in SRC


def test_actions_conservees_avec_confirmation():
    for f in ("torSet", "torNewnym", "torLeaks", "applyExitCountry", "clearExitCountry",
              "addVpnClient", "removeVpnClient", "addBridge", "removeBridge",
              "emancipateWebui", "refreshTorTab"):
        assert "function " + f + "(" in SRC, f
    assert "function ask(" in SRC and "if(DEMO_ON)" in SRC
