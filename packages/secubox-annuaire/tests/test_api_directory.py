# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_api_directory.py
Wiring smoke tests for the directory HTTP endpoints (gondwana P1, #768).

The verbs are exhaustively covered in test_directory.py; here we only verify
the thin FastAPI layer wires correctly (routes registered, request models map
to verb args, responses serialize).
"""
import hashlib

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.model import Identity, MemberState, Op


def _seed_member(journal):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    journal.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload,
                   author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub, did


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    j = apimain.get_journal()
    priv, pub, did = _seed_member(j)
    return TestClient(apimain.app), priv, did


def test_directory_routes_registered(client):
    tc, _priv, _did = client
    paths = {r.path for r in tc.app.routes}
    for p in ("/nodes", "/config", "/log/export", "/node/publish",
              "/config/publish", "/config/revoke", "/log/pull"):
        assert p in paths, f"missing route {p}"


def test_config_publish_then_get(client):
    tc, priv, did = client
    r = tc.post("/config/publish", json={
        "publisher_did": did,
        "publisher_priv_hex": priv.hex(),
        "scope": "yacy",
        "version": 2,
        "content_hash": "b" * 64,
        "payload": {"peer": {"mode": "freeworld"}},
    })
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 2

    g = tc.get("/config")
    assert g.status_code == 200
    configs = g.json()["configs"]
    assert any(c["config_id"] == "cfg-yacy" and c["version"] == 2 for c in configs)


def test_node_publish_then_get(client):
    tc, priv, did = client
    r = tc.post("/node/publish", json={
        "node_did": did,
        "node_priv_hex": priv.hex(),
        "node_id": "sb-aabbccddeeff",
        "boxname": "gk2",
        "pubkey_wg": "W" * 44,
        "mesh_ip": "10.10.0.1",
        "ddns": "gk2.secubox.in",
        "endpoint": "82.67.100.75:51822",
    })
    assert r.status_code == 200, r.text
    g = tc.get("/nodes")
    assert any(n["mesh_ip"] == "10.10.0.1" for n in g.json()["nodes"])


def test_log_export_includes_pubkey(client):
    tc, priv, did = client
    tc.post("/config/publish", json={
        "publisher_did": did, "publisher_priv_hex": priv.hex(),
        "scope": "dns", "version": 1, "content_hash": "c" * 64,
    })
    ex = tc.get("/log/export")
    assert ex.status_code == 200
    entries = ex.json()["entries"]
    assert entries and all("author_pubkey" in e and "sig" in e for e in entries)


def test_log_pull_unreachable_is_graceful(client):
    tc, _priv, _did = client
    r = tc.post("/log/pull", json={"base_url": "http://127.0.0.1:1/"})
    assert r.status_code == 200
    body = r.json()
    assert body["ingested"] == 0 and "error" in body
