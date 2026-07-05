# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the unified discovery merge.

Covers `discover()` merging dnsmasq leases + ISC dhcpd.leases + `ip neigh`
ARP into one canonical device dict per MAC, and the fail-safe contract:
any single source failing must never raise and must contribute nothing
(#817 Device Guardian consolidation, Task 2).
"""


def test_discover_merges(tmp_path):
    from api.discovery import discover
    dns = tmp_path/"dnsmasq.leases"; dns.write_text("1700000000 aa:bb:cc:00:00:10 10.0.0.10 host-a *\n")
    isc = tmp_path/"dhcpd.leases"; isc.write_text('lease 10.0.0.11 {\n hardware ethernet AA:BB:CC:00:00:11;\n client-hostname "host-b";\n}\n')
    arp = lambda: "10.0.0.10 dev br0 lladdr aa:bb:cc:00:00:10 REACHABLE\n10.0.0.12 dev br0 lladdr aa:bb:cc:00:00:12 STALE\n"
    out = {d["mac"]: d for d in discover(dnsmasq_leases=str(dns), isc_leases=str(isc), arp_cmd=arp)}
    assert set(out) == {"aa:bb:cc:00:00:10","aa:bb:cc:00:00:11","aa:bb:cc:00:00:12"}
    assert out["aa:bb:cc:00:00:10"]["hostname"] == "host-a"   # dnsmasq wins over bare arp
    assert out["aa:bb:cc:00:00:11"]["source"] == "isc"
    assert out["aa:bb:cc:00:00:12"]["source"] == "arp"

def test_discover_failsafe(tmp_path):
    from api.discovery import discover
    out = discover(dnsmasq_leases=str(tmp_path/"missing"), isc_leases=str(tmp_path/"missing2"), arp_cmd=lambda: (_ for _ in ()).throw(OSError()))
    assert out == []
