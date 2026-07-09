# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf"


def test_prerouting_chain_and_set_present():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "set tor_vpn_src" in nft
    # a prerouting nat chain that redirects listed sources to TransPort/DNSPort
    assert "prerouting" in nft and "9040" in nft and "9053" in nft
    assert "ip saddr @tor_vpn_src" in nft


def test_dns_redirect_before_exempt_return():
    # DNS(53) redirect MUST precede the tor_exempt return in prerouting_vpn,
    # else a client's DNS server (its own gateway = the box LAN IP, which is
    # in tor_exempt) returns early and leaks the query over the clear WAN.
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    chain = nft.split("chain prerouting_vpn", 1)[1]
    dns_pos = chain.index("th dport 53 redirect to :9053")
    exempt_pos = chain.index("ip daddr @tor_exempt return")
    assert dns_pos < exempt_pos


def test_forward_killswitch_present():
    # Fail-closed: routed clients' non-redirected/non-local egress is DROPPED.
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "chain forward_vpn_killswitch" in nft
    ks = nft.split("chain forward_vpn_killswitch", 1)[1]
    assert "ip saddr @tor_vpn_src drop" in ks
