# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.reach acceptance — real_ip gate effectiveness (ref #793).

We can't spin up nginx in unit tests, so this proves the *semantics* of the
generated allow/deny snippet deterministically with a tiny pure matcher that
emulates nginx's allow/deny directive evaluation (first matching allow wins,
terminal `deny all;` denies the rest, empty snippet == no restriction).

Live effectiveness additionally requires secubox-hub's lan-geo
`set_real_ip_from`/`real_ip_header` so `$remote_addr` reflects the true client
behind HAProxy/mitmproxy — see the exposure README for that wiring; this test
only proves the snippet's own logic is correct.
"""
import sys
from pathlib import Path
import ipaddress

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

from api.reach import reach_snippet


def _would_allow(snippet: str, client_ip: str) -> bool:
    # emulate nginx allow/deny: first matching allow → allow; deny all → deny;
    # empty snippet (wan) → allow (no restriction)
    if snippet.strip() == "":
        return True
    ip = ipaddress.ip_address(client_ip)
    for line in snippet.splitlines():
        line = line.strip().rstrip(";")
        if line.startswith("allow "):
            cidr = line.split()[1]
            net = ipaddress.ip_network(cidr, strict=False)
            if ip in net:
                return True
        elif line == "deny all":
            return False
    return True


def test_lan_snippet_denies_external_allows_lan_and_localhost():
    s = reach_snippet("lan", False)
    assert _would_allow(s, "203.0.113.7") is False
    assert _would_allow(s, "10.20.30.40") is True
    assert _would_allow(s, "127.0.0.1") is True


def test_localhost_snippet_denies_external_and_lan_allows_only_localhost():
    s = reach_snippet("localhost", False)
    assert _would_allow(s, "203.0.113.7") is False
    # localhost does NOT admit LAN — this is what distinguishes it from lan
    assert _would_allow(s, "10.20.30.40") is False
    assert _would_allow(s, "127.0.0.1") is True


def test_lan_plus_mesh_allows_mesh_denies_external():
    s = reach_snippet("lan", True)
    assert _would_allow(s, "10.10.0.5") is True
    assert _would_allow(s, "203.0.113.7") is False


def test_wan_snippet_allows_external():
    s = reach_snippet("wan", False)
    assert _would_allow(s, "203.0.113.7") is True
