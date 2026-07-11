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

def test_isc_latest_lease_wins(tmp_path):
    # dhcpd.leases appends a fresh `lease` block on every renewal; the
    # LATEST block for a MAC must win the ip/hostname, not the first.
    from api.discovery import discover
    isc = tmp_path/"dhcpd.leases"
    isc.write_text(
        'lease 10.0.0.20 {\n hardware ethernet AA:BB:CC:00:00:20;\n client-hostname "old-host";\n}\n'
        'lease 10.0.0.21 {\n hardware ethernet AA:BB:CC:00:00:20;\n client-hostname "new-host";\n}\n'
    )
    out = {d["mac"]: d for d in discover(dnsmasq_leases=str(tmp_path/"missing"), isc_leases=str(isc), arp_cmd=lambda: "")}
    assert set(out) == {"aa:bb:cc:00:00:20"}
    assert out["aa:bb:cc:00:00:20"]["ip"] == "10.0.0.21"
    assert out["aa:bb:cc:00:00:20"]["hostname"] == "new-host"


def test_arp_records_interface_and_includes_br_lxc(tmp_path):
    """ARP sightings carry the interface, and br-lxc is a scanned LAN bridge
    (so LXC containers are discovered and can auto-classify into `lxc`)."""
    from api.discovery import discover
    arp = lambda: "10.1.0.5 dev br-lxc lladdr aa:bb:cc:00:00:30 REACHABLE\n"
    out = {d["mac"]: d for d in discover(dnsmasq_leases=str(tmp_path/"missing"), isc_leases=str(tmp_path/"missing2"), arp_cmd=arp)}
    assert out["aa:bb:cc:00:00:30"]["interface"] == "br-lxc"


def test_interface_survives_higher_rank_lease(tmp_path):
    """A br-lxc container that also has a dnsmasq lease keeps its ARP interface
    (the lease sighting owns source/hostname but must not drop the interface)."""
    from api.discovery import discover
    dns = tmp_path/"dnsmasq.leases"; dns.write_text("1700000000 aa:bb:cc:00:00:31 10.1.0.6 ct-a *\n")
    arp = lambda: "10.1.0.6 dev br-lxc lladdr aa:bb:cc:00:00:31 REACHABLE\n"
    out = {d["mac"]: d for d in discover(dnsmasq_leases=str(dns), isc_leases=str(tmp_path/"missing"), arp_cmd=arp)}
    d = out["aa:bb:cc:00:00:31"]
    assert d["source"] == "dnsmasq" and d["hostname"] == "ct-a"  # lease still wins these
    assert d["interface"] == "br-lxc"                            # ...but interface survives
