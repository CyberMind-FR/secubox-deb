# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from api import ephemeral as e


def test_in_range_and_host_of():
    assert e.in_range("10.11.0.2") is True
    assert e.in_range("10.10.0.2") is False       # wg-mesh range, not ephemeral
    assert e.in_range("nonsense") is False
    assert e.host_of("10.11.0.5/32") == "10.11.0.5"
    with pytest.raises(ValueError):
        e.host_of("10.11.0.5/24")


def test_record_replace_and_remove_roundtrip(tmp_path):
    reg = {"boot_id": "b1", "peers": []}
    e.record_peer(reg, "PK1", "10.11.0.2", "did:plc:" + "a"*32, "1.2.3.4:51820",
                  "2026-07-27T12:00:00Z")
    e.record_peer(reg, "PK1b", "10.11.0.2", "did:plc:" + "a"*32, "1.2.3.4:51820",
                  "2026-07-27T13:00:00Z")  # same ip -> replace
    assert len(reg["peers"]) == 1 and reg["peers"][0]["pubkey"] == "PK1b"
    p = tmp_path / "r.json"
    e.save(reg, str(p)); reg2 = e.load(str(p))
    assert reg2["peers"][0]["ip"] == "10.11.0.2"
    removed = e.remove_by_ip(reg2, "10.11.0.2")
    assert removed and reg2["peers"] == []


def test_remove_by_did_and_expired_failclosed():
    did = "did:plc:" + "c"*32
    reg = {"boot_id": "b1", "peers": [
        {"pubkey": "P", "ip": "10.11.0.2", "did": did, "endpoint": "e",
         "expires_ts": "2999-01-01T00:00:00Z"},
        {"pubkey": "Q", "ip": "10.11.0.3", "did": did, "endpoint": "e",
         "expires_ts": "malformed"},
    ]}
    # expired: past OR unparseable (fail-closed)
    exp = e.expired(reg, "2026-07-27T12:00:00Z")
    assert {p["ip"] for p in exp} == {"10.11.0.3"}   # malformed swept; 2999 not
    assert len(e.remove_by_did(reg, did)) == 2 and reg["peers"] == []


def test_boot_flush():
    reg = {"boot_id": "OLD", "peers": [{"pubkey": "P", "ip": "10.11.0.2",
           "did": "d", "endpoint": "e", "expires_ts": "z"}]}
    flushed, did_flush = e.boot_flush(reg, "NEW")
    assert did_flush is True and flushed == {"boot_id": "NEW", "peers": []}
    same, did2 = e.boot_flush(flushed, "NEW")
    assert did2 is False and same["peers"] == []


def test_load_missing_is_failsafe(tmp_path):
    reg = e.load(str(tmp_path / "nope.json"))
    assert reg == {"boot_id": None, "peers": []}


def test_in_range_excludes_network_and_broadcast():
    assert e.in_range("10.11.0.0") is False      # network address
    assert e.in_range("10.11.0.255") is False     # broadcast
    assert e.in_range("10.11.0.1") is True         # box addr allowed


def test_expired_failclosed_on_non_string_ts():
    reg = {"boot_id": "b", "peers": [
        {"pubkey": "P", "ip": "10.11.0.2", "did": "d", "endpoint": "e",
         "expires_ts": 12345},                      # non-string malformed
    ]}
    # must NOT raise, and must sweep the malformed entry
    assert e.expired(reg, "2026-07-27T12:00:00Z") == reg["peers"]


def test_load_missing_returns_independent_dicts(tmp_path):
    r1 = e.load(str(tmp_path / "a.json")); r2 = e.load(str(tmp_path / "b.json"))
    r1["peers"].append({"x": 1})
    assert r2["peers"] == []                        # not contaminated
