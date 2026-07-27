# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
from annuaire import fleet
from annuaire.crypto import public_from_private, did_from_pubkey

FIELDS = dict(hostname="gk2", ts="2026-07-27T10:00:00Z", cpu_pct=10.0, mem_pct=20.0,
              disk_pct=30.0, load1=0.5, uptime_s=100, modules_up=5, modules_down=[],
              counters={"bans": 0, "assist_sessions": 0, "soc_alerts": 0})


def _signed(priv):
    did = did_from_pubkey(public_from_private(priv))
    return fleet.sign_snapshot(priv, {**FIELDS, "node_did": did, "issued_by": did})


def test_sign_then_verify_roundtrip():
    priv = os.urandom(32)
    rec = _signed(priv)
    assert fleet.verify_snapshot(rec) is True


def test_tampered_field_fails_verify():
    priv = os.urandom(32)
    rec = _signed(priv); rec["cpu_pct"] = 99.0   # tamper after signing
    assert fleet.verify_snapshot(rec) is False


def test_foreign_signer_did_rejected():
    priv = os.urandom(32); other = os.urandom(32)
    rec = _signed(priv)
    rec["node_did"] = did_from_pubkey(public_from_private(other))  # claim another did
    assert fleet.verify_snapshot(rec) is False


def test_fleet_snapshots_keeps_only_verified():
    p1, p2 = os.urandom(32), os.urandom(32)
    r1, r2 = _signed(p1), _signed(p2)
    forged = _signed(os.urandom(32)); forged["sig"] = "00" * 64  # broken sig
    out = fleet.fleet_snapshots(r1, [r2, forged])
    assert set(out) == {r1["node_did"], r2["node_did"]}


def test_is_stale_failclosed():
    assert fleet.is_stale({"ts": "garbage"}, "2026-07-27T10:00:00Z", 300) is True
    assert fleet.is_stale({"ts": "2026-07-27T10:00:00Z"}, "2026-07-27T10:02:00Z", 300) is False
    assert fleet.is_stale({"ts": "2026-07-27T10:00:00Z"}, "2026-07-27T10:10:00Z", 300) is True
