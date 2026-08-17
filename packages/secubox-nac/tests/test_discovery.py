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

def test_resolve_hostname_reverse_dns(monkeypatch):
    """Primary path: a successful reverse-DNS lookup is stripped to its
    short, lowercased form (#820, ref #817)."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()
    monkeypatch.setattr(discovery, "_reverse_dns", lambda ip: "Pop-OS.home")
    assert discovery.resolve_hostname("192.168.1.14") == "pop-os"


def test_resolve_hostname_raising_resolver_is_none(monkeypatch):
    """A reverse-DNS call that raises/times out must never propagate —
    resolve_hostname degrades to None."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()

    def _boom(ip):
        raise TimeoutError("bounded resolver timed out")

    monkeypatch.setattr(discovery, "_reverse_dns", _boom)
    monkeypatch.setattr(discovery, "_mdns_resolve", lambda ip: None)
    assert discovery.resolve_hostname("192.168.1.99") is None


def test_resolve_hostname_ip_echo_is_none(monkeypatch):
    """Some resolvers echo the IP back instead of failing — that must be
    treated as no result, not a real hostname."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()
    monkeypatch.setattr(discovery, "_reverse_dns", lambda ip: ip)
    monkeypatch.setattr(discovery, "_mdns_resolve", lambda ip: None)
    assert discovery.resolve_hostname("192.168.1.50") is None


def test_resolve_hostname_cached_no_reinvoke(monkeypatch):
    """Second call for the same IP within the TTL must NOT re-invoke the
    underlying resolver (proven via a call-count spy)."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()
    calls = {"n": 0}

    def _spy(ip):
        calls["n"] += 1
        return "squeezeboxradio.home"

    monkeypatch.setattr(discovery, "_reverse_dns", _spy)
    first = discovery.resolve_hostname("192.168.1.91")
    second = discovery.resolve_hostname("192.168.1.91")
    assert first == second == "squeezeboxradio"
    assert calls["n"] == 1


def test_resolve_hostname_negative_result_cached(monkeypatch):
    """A cached None (no PTR) must also short-circuit the resolver on the
    next call — don't hammer a device with no PTR every cycle."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()
    calls = {"n": 0}

    def _spy(ip):
        calls["n"] += 1
        return None

    monkeypatch.setattr(discovery, "_reverse_dns", _spy)
    monkeypatch.setattr(discovery, "_mdns_resolve", lambda ip: None)
    assert discovery.resolve_hostname("192.168.1.200") is None
    assert discovery.resolve_hostname("192.168.1.200") is None
    assert calls["n"] == 1


def test_resolve_hostname_mdns_fallback(monkeypatch):
    """mDNS only runs when reverse-DNS found nothing."""
    from api import discovery
    discovery._HOSTNAME_CACHE.clear()
    monkeypatch.setattr(discovery, "_reverse_dns", lambda ip: None)
    monkeypatch.setattr(discovery, "_mdns_resolve", lambda ip: "c3box3.local")
    assert discovery.resolve_hostname("192.168.1.94") == "c3box3"


def test_discover_fills_empty_hostname_via_resolver(monkeypatch):
    """An ARP-only sighting (no hostname) whose IP resolves gets its
    hostname filled from the resolver (#820, ref #817)."""
    from api import discovery
    arp = lambda: "10.0.0.30 dev br0 lladdr aa:bb:cc:00:00:30 REACHABLE\n"
    monkeypatch.setattr(discovery, "resolve_hostname", lambda ip: "pop-os" if ip == "10.0.0.30" else None)
    out = {d["mac"]: d for d in discovery.discover(
        dnsmasq_leases="/nonexistent/dnsmasq", isc_leases="/nonexistent/isc", arp_cmd=arp)}
    assert out["aa:bb:cc:00:00:30"]["hostname"] == "pop-os"
    assert out["aa:bb:cc:00:00:30"]["source"] == "arp"


def test_discover_does_not_overwrite_lease_hostname(monkeypatch, tmp_path):
    """A device that already has a lease-backed hostname must NOT be
    touched by the resolver, even if the resolver would return something
    different."""
    from api import discovery
    dns = tmp_path / "dnsmasq.leases"
    dns.write_text("1700000000 aa:bb:cc:00:00:31 10.0.0.31 host-a *\n")
    monkeypatch.setattr(discovery, "resolve_hostname", lambda ip: "should-not-be-used")
    out = {d["mac"]: d for d in discovery.discover(
        dnsmasq_leases=str(dns), isc_leases="/nonexistent/isc", arp_cmd=lambda: "")}
    assert out["aa:bb:cc:00:00:31"]["hostname"] == "host-a"


def test_discover_resolver_none_leaves_hostname_empty():
    """A resolver returning None for a hostname-less ARP sighting leaves
    the hostname empty (no crash, no bogus value)."""
    from api import discovery
    arp = lambda: "10.0.0.32 dev br0 lladdr aa:bb:cc:00:00:32 REACHABLE\n"
    discovery._HOSTNAME_CACHE.clear()
    # No network in CI: the real reverse-DNS lookup will fail/timeout on
    # this bogus IP and resolve_hostname degrades to None, per contract.
    out = {d["mac"]: d for d in discovery.discover(
        dnsmasq_leases="/nonexistent/dnsmasq", isc_leases="/nonexistent/isc", arp_cmd=arp)}
    assert out["aa:bb:cc:00:00:32"]["hostname"] == ""


def test_discover_resolver_raising_is_failsafe(monkeypatch):
    """resolve_hostname raising must never abort discover() — the device
    is still returned, just without a filled hostname."""
    from api import discovery
    arp = lambda: "10.0.0.33 dev br0 lladdr aa:bb:cc:00:00:33 REACHABLE\n"

    def _boom(ip):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(discovery, "resolve_hostname", _boom)
    out = {d["mac"]: d for d in discovery.discover(
        dnsmasq_leases="/nonexistent/dnsmasq", isc_leases="/nonexistent/isc", arp_cmd=arp)}
    assert out["aa:bb:cc:00:00:33"]["hostname"] == ""


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
