# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_fleet_api.py
Pytest coverage for the /fleet HTTP endpoints (feat/fleet-metrics, Task 4).

- GET /fleet/self mirrors GET /log/export: public, no JWT, returns the local
  signed fleet_store record verbatim (or {} when this node hasn't published
  yet). This is what peers pull on :8799.
- GET /fleet is JWT-gated: aggregates self_rec + verified peer records
  (pulled from mesh_sync.read_mesh_peers() via the module-level, injectable
  _fetch_fleet_peer) through annuaire.fleet.fleet_snapshots, annotating each
  with health/stale. Read-only, must never 500 — an unreachable/raising peer
  is dropped, not fatal.
"""
from __future__ import annotations

import pytest

from annuaire import fleet, fleet_store
from annuaire.crypto import did_from_pubkey, generate_keypair

FIELDS = dict(
    hostname="gk2", ts="2026-07-27T10:00:00Z", cpu_pct=10.0, mem_pct=20.0,
    disk_pct=30.0, load1=0.5, uptime_s=100, modules_up=5, modules_down=[],
    counters={"bans": 0, "assist_sessions": 0, "soc_alerts": 0},
)


def _actor():
    priv, pub = generate_keypair()
    return priv, pub, did_from_pubkey(pub)


def _signed(priv, did):
    return fleet.sign_snapshot(priv, {**FIELDS, "node_did": did, "issued_by": did})


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")  # no background loop in tests
    monkeypatch.setenv("FLEET_SELF_PATH", str(tmp_path / "self.json"))

    # fleet_store.SELF_PATH (and read()/write()'s default `path` kwarg) are
    # bound at module-import time from the env var — reload so this test's
    # FLEET_SELF_PATH actually takes effect (mirrors test_fleet_store.py's
    # test_default_path_env_override idiom). api/main.py holds a reference to
    # this SAME module object, so the reload is visible through apimain too.
    import importlib
    from annuaire import fleet_store as _fleet_store_mod
    importlib.reload(_fleet_store_mod)

    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    try:
        yield TestClient(apimain.app), apimain
    finally:
        importlib.reload(_fleet_store_mod)


# ---------------------------------------------------------------------------
# routes registered
# ---------------------------------------------------------------------------


def test_fleet_routes_registered(client):
    tc, _apimain = client
    paths = {r.path for r in tc.app.routes}
    assert "/fleet/self" in paths
    assert "/fleet" in paths


# ---------------------------------------------------------------------------
# /fleet/self — public read-path
# ---------------------------------------------------------------------------


def test_fleet_self_returns_stored_record(client, tmp_path):
    tc, _apimain = client
    priv, _pub, did = _actor()
    rec = _signed(priv, did)
    fleet_store.write(rec, path=str(tmp_path / "self.json"))

    r = tc.get("/fleet/self")
    assert r.status_code == 200
    assert r.json() == rec


def test_fleet_self_empty_dict_when_unpublished(client):
    tc, _apimain = client
    r = tc.get("/fleet/self")
    assert r.status_code == 200
    assert r.json() == {}


def test_fleet_self_route_not_jwt_gated(client):
    tc, apimain = client
    for route in tc.app.routes:
        if route.path == "/fleet/self":
            calls = [dep.call for dep in route.dependant.dependencies]
            assert apimain._require_jwt not in calls
            return
    pytest.fail("no /fleet/self route found")


# ---------------------------------------------------------------------------
# /fleet — JWT gated
# ---------------------------------------------------------------------------


def test_fleet_route_requires_jwt(client):
    tc, apimain = client
    for route in tc.app.routes:
        if route.path == "/fleet":
            calls = [dep.call for dep in route.dependant.dependencies]
            assert apimain._require_jwt in calls
            return
    pytest.fail("no /fleet route found")


def test_fleet_aggregates_self_and_verified_peer(client, tmp_path, monkeypatch):
    tc, apimain = client
    priv, _pub, did = _actor()
    self_rec = _signed(priv, did)
    fleet_store.write(self_rec, path=str(tmp_path / "self.json"))

    peer_priv, _peer_pub, peer_did = _actor()
    peer_rec = _signed(peer_priv, peer_did)

    monkeypatch.setattr(
        apimain.mesh_sync, "read_mesh_peers",
        lambda *a, **k: [{"mesh_ip": "10.10.0.2", "name": "peer"}],
    )
    monkeypatch.setattr(apimain, "_fetch_fleet_peer", lambda url, timeout=2: peer_rec)

    r = tc.get("/fleet")
    assert r.status_code == 200
    body = r.json()
    nodes = {n["node_did"]: n for n in body["nodes"]}
    assert set(nodes) == {did, peer_did}
    for n in nodes.values():
        assert n["health"] == "ok"
        assert n["stale"] is False


def test_fleet_drops_unverified_peer(client, tmp_path, monkeypatch):
    tc, apimain = client
    priv, _pub, did = _actor()
    self_rec = _signed(priv, did)
    fleet_store.write(self_rec, path=str(tmp_path / "self.json"))

    forged = {**self_rec, "node_did": "did:plc:" + "f" * 32}  # tampered, won't verify

    monkeypatch.setattr(
        apimain.mesh_sync, "read_mesh_peers",
        lambda *a, **k: [{"mesh_ip": "10.10.0.3", "name": "forger"}],
    )
    monkeypatch.setattr(apimain, "_fetch_fleet_peer", lambda url, timeout=2: forged)

    r = tc.get("/fleet")
    assert r.status_code == 200
    nodes = {n["node_did"] for n in r.json()["nodes"]}
    assert nodes == {did}


def test_fleet_peer_fetch_raising_does_not_500(client, tmp_path, monkeypatch):
    tc, apimain = client
    priv, _pub, did = _actor()
    self_rec = _signed(priv, did)
    fleet_store.write(self_rec, path=str(tmp_path / "self.json"))

    monkeypatch.setattr(
        apimain.mesh_sync, "read_mesh_peers",
        lambda *a, **k: [{"mesh_ip": "10.10.0.9", "name": "unreachable"}],
    )

    def _boom(url, timeout=2):
        raise TimeoutError("no route to host")

    monkeypatch.setattr(apimain, "_fetch_fleet_peer", _boom)

    r = tc.get("/fleet")
    assert r.status_code == 200
    nodes = {n["node_did"] for n in r.json()["nodes"]}
    assert nodes == {did}


def test_fleet_aggregates_peers_concurrently_and_drops_failures(client, tmp_path, monkeypatch):
    """Multiple peers are pulled via asyncio.gather(to_thread(...)); a raising
    peer and a None-returning peer are both dropped, only the verified peer
    survives alongside self (proves the concurrent-fetch + drop-on-failure
    path introduced to stop /fleet from serially blocking the shared loop)."""
    tc, apimain = client
    priv, _pub, did = _actor()
    self_rec = _signed(priv, did)
    fleet_store.write(self_rec, path=str(tmp_path / "self.json"))

    good_priv, _good_pub, good_did = _actor()
    good_rec = _signed(good_priv, good_did)

    monkeypatch.setattr(
        apimain.mesh_sync, "read_mesh_peers",
        lambda *a, **k: [
            {"mesh_ip": "10.10.0.2", "name": "good"},
            {"mesh_ip": "10.10.0.9", "name": "raiser"},
            {"mesh_ip": "10.10.0.5", "name": "none-peer"},
        ],
    )

    def _fetch(url, timeout=2):
        if "10.10.0.2" in url:
            return good_rec
        if "10.10.0.9" in url:
            raise TimeoutError("no route to host")
        return None  # "none-peer"

    monkeypatch.setattr(apimain, "_fetch_fleet_peer", _fetch)

    r = tc.get("/fleet")
    assert r.status_code == 200
    nodes = {n["node_did"] for n in r.json()["nodes"]}
    assert nodes == {did, good_did}


def test_fleet_no_peers_no_self_returns_empty_nodes(client, monkeypatch):
    tc, apimain = client
    monkeypatch.setattr(apimain.mesh_sync, "read_mesh_peers", lambda *a, **k: [])

    r = tc.get("/fleet")
    assert r.status_code == 200
    assert r.json() == {"nodes": []}


def test_fleet_never_500_on_unexpected_failure(client, monkeypatch):
    tc, apimain = client

    def _explode():
        raise RuntimeError("store corrupt")

    monkeypatch.setattr(apimain.fleet_store, "read", _explode)

    r = tc.get("/fleet")
    assert r.status_code == 200
    assert r.json() == {"nodes": []}
