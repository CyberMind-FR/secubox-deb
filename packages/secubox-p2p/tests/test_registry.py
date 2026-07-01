# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: tests :: test_registry
Test the pure merge logic and activation overlay.
"""
import json
from api import registry


def test_port_from_endpoint():
    assert registry.port_from_endpoint("http://10.10.0.1:9050/x") == 9050
    assert registry.port_from_endpoint("10.10.0.2:3483") == 3483
    assert registry.port_from_endpoint("/local/path") is None
    assert registry.port_from_endpoint("") is None


def test_merge_local_vs_remote_and_state():
    local_did = "did:plc:" + "a" * 32
    remote_did = "did:plc:" + "b" * 32
    catalog = [
        {"service_id": "s1", "name": "WAF mirror", "kind": "module",
         "provider": local_did, "endpoint": "http://10.10.0.1:8085",
         "approval_mode": "auto"},
        {"service_id": "s2", "name": "Tor exit", "kind": "tor-exit",
         "provider": remote_did, "endpoint": "10.10.0.2:9050",
         "approval_mode": "pending"},
    ]
    subs = [{"service_id": "s2", "state": "pending"}]
    overlay = {"s1": {"active": True, "local_port": 8085, "subscription_id": None}}
    rows = registry.merge_services(catalog, subs, overlay, [], local_did)
    by_id = {r["service_id"]: r for r in rows}
    assert by_id["s1"]["provider_label"] == "local"
    assert by_id["s1"]["active"] is True
    assert by_id["s1"]["subscription_state"] == "not-subscribed"
    assert by_id["s2"]["provider_label"] != "local"
    assert by_id["s2"]["subscription_state"] == "pending"
    assert by_id["s2"]["automatable"] is True       # tor-exit ∈ MACRO_KINDS
    assert by_id["s1"]["automatable"] is False


def test_merge_includes_legacy_local():
    legacy = [{"name": "old-svc", "port": 1234, "protocol": "tcp", "active": True}]
    rows = registry.merge_services([], [], {}, legacy, None)
    assert len(rows) == 1
    assert rows[0]["source"] == "p2p-local"
    assert rows[0]["provider_label"] == "local"
    assert rows[0]["port"] == 1234


def test_overlay_roundtrip_and_prune(tmp_path):
    p = tmp_path / "activation.json"
    registry.set_active(str(p), "s1", 8085)
    data = registry.load_overlay(str(p))
    assert data["s1"]["active"] is True and data["s1"]["local_port"] == 8085
    # prune: merge drops overlay-only entries with no catalog/legacy backing
    rows = registry.merge_services([], [], data, [], None)
    assert rows == []


def test_load_overlay_missing_or_corrupt(tmp_path):
    assert registry.load_overlay(str(tmp_path / "nope.json")) == {}
    bad = tmp_path / "bad.json"; bad.write_text("{not json")
    assert registry.load_overlay(str(bad)) == {}


def test_overlay_endpoint_surfaces_in_merged_row(tmp_path):
    """Overlay entry with endpoint set by _macroctl_activate should appear in the merged row."""
    p = tmp_path / "activation.json"
    socks_ep = "10.10.0.1:9050"
    registry.set_active(str(p), "tor-s1", 9050, endpoint=socks_ep)
    data = registry.load_overlay(str(p))
    assert data["tor-s1"]["endpoint"] == socks_ep

    remote_did = "did:plc:" + "c" * 32
    catalog = [
        {"service_id": "tor-s1", "name": "Tor exit", "kind": "tor-exit",
         "provider": remote_did, "endpoint": "http://10.10.0.1/tor",
         "approval_mode": "auto"},
    ]
    rows = registry.merge_services(catalog, [], data, [], None)
    assert len(rows) == 1
    row = rows[0]
    assert row["active"] is True
    assert row["automatable"] is True
    assert row.get("endpoint") == socks_ep


def test_overlay_endpoint_absent_when_not_set():
    """Rows without an overlay endpoint must NOT carry an 'endpoint' key."""
    remote_did = "did:plc:" + "d" * 32
    catalog = [
        {"service_id": "wg-s1", "name": "WG relay", "kind": "wg-relay",
         "provider": remote_did, "endpoint": "10.10.0.2:51820",
         "approval_mode": "auto"},
    ]
    overlay = {"wg-s1": {"active": True, "local_port": 51820}}
    rows = registry.merge_services(catalog, [], overlay, [], None)
    assert len(rows) == 1
    assert "endpoint" not in rows[0]
