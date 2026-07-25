# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_centers_api
Pytest coverage for the /centers HTTP endpoints (feat/centers-grants-remote-
config, Task 8) — read endpoints resolve in-process from the journal
(annuaire.grants); mutating endpoints delegate to sbx-centersctl, mirroring
the monkeypatched-ctl idiom already used by secubox-proxypac's api/main.py
(there: `_ctl`; here: `api.main._centers_ctl`).

Tests:
  - GET /centers/ownership reflects a grant seeded directly into the test
    journal via annuaire.verbs.grant_issue.
  - GET /centers groups the same grant by center_did.
  - POST /centers/grant delegates to sbx-centersctl with
    ["grant", center_did, scope, layer] (monkeypatched _centers_ctl).
  - A non-delegatable scope — ctl returns rc!=0, stderr JSON
    {"error": "scope-not-delegatable"} — propagates as HTTP 400 with that
    message as the detail.
  - POST /centers/revoke delegates to ["revoke", grant_id].
  - POST /centers/proposal/accept delegates grant THEN route, in order, and
    stops (never calls route) if the grant step fails.
  - GET /centers/proposals and GET /centers/effective/{scope} are wired and
    return the read-only route_config(apply=False) shape on an empty journal.
  - The three mutating endpoints declare Depends(_require_jwt).
"""
from __future__ import annotations

import json

import pytest

from annuaire.crypto import did_from_pubkey, generate_keypair
from annuaire.verbs import grant_issue


def _actor():
    priv, pub = generate_keypair()
    return priv, pub, did_from_pubkey(pub)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")  # no background loop in tests
    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    return TestClient(apimain.app), apimain


# ---------------------------------------------------------------------------
# Read endpoints — resolved in-process from the journal
# ---------------------------------------------------------------------------


def test_centers_ownership_reflects_seeded_grant(client):
    tc, apimain = client
    j = apimain.get_journal()
    box_priv, _box_pub, box_did = _actor()
    _c_priv, _c_pub, center_did = _actor()

    grant_issue(j, box_priv, box_did, center_did, "firewall", "baseline")

    r = tc.get("/centers/ownership")
    assert r.status_code == 200
    matrix = r.json()["ownership"]
    assert len(matrix) == 1
    assert matrix[0]["scope"] == "firewall"
    assert matrix[0]["layer"] == "baseline"
    assert matrix[0]["owner"] == center_did


def test_centers_list_groups_by_center(client):
    tc, apimain = client
    j = apimain.get_journal()
    box_priv, _box_pub, box_did = _actor()
    _c_priv, _c_pub, center_did = _actor()

    grant_issue(j, box_priv, box_did, center_did, "firewall", "baseline")
    grant_issue(j, box_priv, box_did, center_did, "dns", "override")

    r = tc.get("/centers")
    assert r.status_code == 200
    centers = r.json()["centers"]
    assert len(centers) == 1
    assert centers[0]["center_did"] == center_did
    scopes = {(g["scope"], g["layer"]) for g in centers[0]["grants"]}
    assert scopes == {("firewall", "baseline"), ("dns", "override")}


def test_centers_ownership_empty_journal(client):
    tc, _apimain = client
    r = tc.get("/centers/ownership")
    assert r.status_code == 200
    assert r.json() == {"ownership": []}


def test_centers_proposals_route_wired(client):
    tc, _apimain = client
    r = tc.get("/centers/proposals")
    assert r.status_code == 200
    assert r.json() == {"proposals": []}


def test_centers_effective_no_layers(client):
    tc, _apimain = client
    r = tc.get("/centers/effective/nosuchscope")
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "nosuchscope"
    assert body["status"] == "no-layers"
    assert body["effective"] is None
    assert body["local"] is None


# ---------------------------------------------------------------------------
# Mutating endpoints — delegate to sbx-centersctl via _centers_ctl
# ---------------------------------------------------------------------------


def test_centers_grant_delegates_to_ctl(client, monkeypatch):
    tc, apimain = client
    _priv, _pub, center_did = _actor()
    captured = {}

    def fake_ctl(args, timeout=25):
        captured["args"] = args
        return 0, json.dumps({
            "grant_id": "g1", "center_did": center_did,
            "scope": "firewall", "layer": "baseline",
        }), ""

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/grant", json={
        "center_did": center_did, "scope": "firewall", "layer": "baseline",
    })
    assert r.status_code == 200, r.text
    assert r.json()["grant_id"] == "g1"
    assert captured["args"] == ["grant", center_did, "firewall", "baseline"]


def test_centers_grant_non_delegatable_scope_returns_400(client, monkeypatch):
    tc, apimain = client
    _priv, _pub, center_did = _actor()

    def fake_ctl(args, timeout=25):
        return 1, "", json.dumps({"error": "scope-not-delegatable"})

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/grant", json={
        "center_did": center_did, "scope": "auth", "layer": "baseline",
    })
    assert r.status_code == 400
    assert r.json()["detail"] == "scope-not-delegatable"


def test_centers_revoke_delegates_to_ctl(client, monkeypatch):
    tc, apimain = client
    captured = {}

    def fake_ctl(args, timeout=25):
        captured["args"] = args
        return 0, json.dumps({"grant_id": "g1", "revoked": True}), ""

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/revoke", json={"grant_id": "g1"})
    assert r.status_code == 200, r.text
    assert captured["args"] == ["revoke", "g1"]
    assert r.json()["revoked"] is True


def test_centers_revoke_failure_returns_400(client, monkeypatch):
    tc, apimain = client

    def fake_ctl(args, timeout=25):
        return 1, "", json.dumps({"error": "no-such-grant"})

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/revoke", json={"grant_id": "nope"})
    assert r.status_code == 400
    assert r.json()["detail"] == "no-such-grant"


def test_centers_proposal_accept_grants_then_routes(client, monkeypatch):
    tc, apimain = client
    _priv, _pub, center_did = _actor()
    calls = []

    def fake_ctl(args, timeout=25):
        calls.append(list(args))
        if args[0] == "grant":
            return 0, json.dumps({"grant_id": "g1"}), ""
        if args[0] == "route":
            return 0, json.dumps({"applied": [], "proposals": []}), ""
        return 1, "", json.dumps({"error": "unexpected"})

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/proposal/accept", json={
        "center_did": center_did, "scope": "firewall", "layer": "baseline",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["grant"]["grant_id"] == "g1"
    assert body["route"]["applied"] == []
    assert [c[0] for c in calls] == ["grant", "route"]
    assert calls[0] == ["grant", center_did, "firewall", "baseline"]
    assert calls[1] == ["route"]


def test_centers_proposal_accept_stops_if_grant_fails(client, monkeypatch):
    tc, apimain = client
    _priv, _pub, center_did = _actor()
    calls = []

    def fake_ctl(args, timeout=25):
        calls.append(list(args))
        return 1, "", json.dumps({"error": "already-owned"})

    monkeypatch.setattr(apimain, "_centers_ctl", fake_ctl)

    r = tc.post("/centers/proposal/accept", json={
        "center_did": center_did, "scope": "firewall", "layer": "baseline",
    })
    assert r.status_code == 400
    assert r.json()["detail"] == "already-owned"
    assert len(calls) == 1  # route never attempted after grant failed


# ---------------------------------------------------------------------------
# JWT gating on mutating endpoints
# ---------------------------------------------------------------------------


def test_centers_mutating_endpoints_require_jwt(client):
    tc, apimain = client
    mutating = {"/centers/grant", "/centers/revoke", "/centers/proposal/accept"}
    seen = set()
    for route in tc.app.routes:
        if route.path in mutating:
            seen.add(route.path)
            calls = [dep.call for dep in route.dependant.dependencies]
            assert apimain._require_jwt in calls, f"{route.path} missing JWT dependency"
    assert seen == mutating


def test_centers_read_endpoints_do_not_require_jwt(client):
    tc, apimain = client
    read_only = {"/centers", "/centers/ownership", "/centers/proposals"}
    for route in tc.app.routes:
        if route.path in read_only:
            calls = [dep.call for dep in route.dependant.dependencies]
            assert apimain._require_jwt not in calls, f"{route.path} unexpectedly JWT-gated"
