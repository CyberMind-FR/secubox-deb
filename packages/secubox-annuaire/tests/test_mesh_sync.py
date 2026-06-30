# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_mesh_sync.py
Directory replication loop (gondwana P1, #768). Network is injected (fetch),
so these are deterministic unit tests.
"""
import hashlib
import json

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.mesh_sync import read_mesh_peers, sync_once
from annuaire.model import Identity, MemberState, Op
from annuaire.verbs import _get_config, export_entries, publish_config


def _make_member(journal):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    journal.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload,
                   author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub, did


# ---------------------------------------------------------------------------
# read_mesh_peers
# ---------------------------------------------------------------------------

def test_read_mesh_peers_parses(tmp_path):
    p = tmp_path / "wg_mesh.json"
    p.write_text(json.dumps({"peers": [
        {"name": "c3box", "mesh_ip": "10.10.0.2"},
        {"name": "amd64", "allowed_ips": "10.10.0.3/32"},  # fall back to allowed_ips
    ]}))
    peers = read_mesh_peers(str(p))
    ips = sorted(x["mesh_ip"] for x in peers)
    assert ips == ["10.10.0.2", "10.10.0.3"]


def test_read_mesh_peers_missing_file_is_empty(tmp_path):
    assert read_mesh_peers(str(tmp_path / "nope.json")) == []


# ---------------------------------------------------------------------------
# sync_once
# ---------------------------------------------------------------------------

def test_sync_once_converges(tmp_path):
    # Producer journal has a config; consumer pulls it via injected fetch.
    prod = Journal(str(tmp_path / "prod.db"))
    priv, pub, did = _make_member(prod)
    publish_config(prod, priv, did, scope="yacy", version=7, content_hash="a" * 64,
                   payload={"k": "v"})
    prod_entries = export_entries(prod)

    consumer = Journal(str(tmp_path / "consumer.db"))

    def fake_fetch(url):
        assert url == "http://10.10.0.2:9080/api/v1/annuaire/log/export"
        return prod_entries

    totals = sync_once(consumer, [{"mesh_ip": "10.10.0.2", "name": "c3box"}], fetch=fake_fetch)
    assert totals["peers"] == 1 and totals["ingested"] >= 2 and totals["rejected"] == 0
    cfg = _get_config(consumer, "cfg-yacy")
    assert cfg is not None and cfg["version"] == 7


def test_sync_once_unreachable_peer_counted_not_raised(tmp_path):
    consumer = Journal(str(tmp_path / "consumer.db"))

    def boom(url):
        raise OSError("connection refused")

    totals = sync_once(consumer, [{"mesh_ip": "10.10.0.9"}], fetch=boom)
    assert totals["errors"] == 1 and totals["peers"] == 0 and totals["ingested"] == 0


def test_sync_once_idempotent(tmp_path):
    prod = Journal(str(tmp_path / "prod.db"))
    priv, pub, did = _make_member(prod)
    publish_config(prod, priv, did, scope="dns", version=1, content_hash="b" * 64)
    entries = export_entries(prod)
    consumer = Journal(str(tmp_path / "consumer.db"))
    peers = [{"mesh_ip": "10.10.0.2"}]
    sync_once(consumer, peers, fetch=lambda u: entries)
    second = sync_once(consumer, peers, fetch=lambda u: entries)
    assert second["ingested"] == 0 and second["skipped"] == len(entries)
