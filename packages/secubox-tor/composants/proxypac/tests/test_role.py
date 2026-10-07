# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from proxypac import role

def probe(dhcp=False, dns=False, lan="192.168.1.200"):
    return {"lan_ip": lan,
            "dhcp_on_lan": dhcp,
            "dns_on_lan": dns}

def test_master_when_dhcp_listens_on_lan():
    r = role.detect(probe(dhcp=True, dns=True))
    assert r["role"] == "master" and r["tier"] == 1

def test_slave_with_dns_is_tier2():
    r = role.detect(probe(dhcp=False, dns=True))
    assert r["role"] == "slave" and r["tier"] == 2 and r["dns_resolver"] is True

def test_slave_without_dns_is_tier3():
    r = role.detect(probe(dhcp=False, dns=False))
    assert r["role"] == "slave" and r["tier"] == 3
