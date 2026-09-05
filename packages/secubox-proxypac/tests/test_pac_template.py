# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from proxypac.pac_template import directive, render

def test_directive_socks_has_failopen():
    assert directive("socks5", "10.10.0.1:9050") == "SOCKS5 10.10.0.1:9050; DIRECT"

def test_directive_http_and_gateway_are_proxy():
    assert directive("http", "127.0.0.1:8081") == "PROXY 127.0.0.1:8081; DIRECT"
    assert directive("gateway", "gk2.secubox.in") == "PROXY gk2.secubox.in; DIRECT"

def test_directive_direct():
    assert directive("direct", "") == "DIRECT"

def test_render_first_match_wins_and_terminal_direct():
    pac = render([("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT")])
    assert "function FindProxyForURL(url, host)" in pac
    assert 'shExpMatch(host, "*.onion")' in pac
    assert 'return "SOCKS5 10.10.0.1:9050; DIRECT";' in pac
    assert pac.rstrip().endswith("}")
    assert 'return "DIRECT";' in pac
