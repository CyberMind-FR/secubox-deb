# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_directory.py
Pytest coverage for the P2P directory primitives (gondwana P1, issue #768).

The annuaire becomes the distributed directory: alongside service offers it
carries signed NodeRecords (the mesh peer registry) and signed ConfigBlobs
(versioned config distribution). This first slice covers the models + Op enum;
verbs, /log pull federation and the p2p publisher land in later slices.
"""
import hashlib

import pytest
from pydantic import ValidationError

from annuaire.crypto import (
    canonical_bytes,
    did_from_pubkey,
    generate_keypair,
    sign,
)
from annuaire.log import Journal
from annuaire.model import (
    ConfigBlob,
    Identity,
    MemberState,
    NodeRecord,
    Op,
    now_rfc3339,
)
from annuaire.resolver import can
from annuaire.verbs import (
    _get_config,
    _get_configs,
    _get_nodes,
    export_entries,
    import_entries,
    ingest_config,
    publish_config,
    publish_node,
    revoke_config,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers (mirror tests/test_services.py)
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_journal(tmp_path):
    return Journal(str(tmp_path / "test.db"))


def _make_member(journal: Journal):
    """Bootstrap a MEMBER node; returns (priv, pub, did)."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.MEMBER)
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    journal.append(
        op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload,
        author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex(),
    )
    return priv, pub, did


def _make_observed(journal: Journal):
    """Bootstrap an OBSERVED node; returns (priv, pub, did)."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.OBSERVED)
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    journal.append(
        op=Op.AUTO_ADD, payload_type="Identity", payload=payload,
        author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex(),
    )
    return priv, pub, did


def _h(s: str) -> str:
    return hashlib.blake2b(s.encode(), digest_size=32).hexdigest()


# ---------------------------------------------------------------------------
# Op enum — the new directory ops
# ---------------------------------------------------------------------------

def test_op_enum_has_directory_members():
    assert Op.NODE_PUBLISH.value == "node_publish"
    assert Op.CONFIG_PUBLISH.value == "config_publish"
    assert Op.CONFIG_REVOKE.value == "config_revoke"


# ---------------------------------------------------------------------------
# NodeRecord — a signed mesh peer registry entry
# ---------------------------------------------------------------------------

def test_node_record_constructable():
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    rec = NodeRecord(
        did=did,
        node_id="sb-aabbccddeeff",
        boxname="gk2",
        pubkey_wg="X" * 44,
        mesh_ip="10.10.0.1",
        ddns="gk2.secubox.in",
        endpoint="82.67.100.75:51822",
    )
    assert rec.node_id == "sb-aabbccddeeff"
    assert rec.mesh_ip == "10.10.0.1"
    assert rec.did == did
    # endpoint is optional (satellites behind NAT have none)
    assert rec.sig is None and rec.signer_did is None


def test_node_record_endpoint_optional():
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    rec = NodeRecord(
        did=did,
        node_id="sb-001122334455",
        boxname="c3box",
        pubkey_wg="Y" * 44,
        mesh_ip="10.10.0.2",
        ddns="c3box.secubox.in",
    )
    assert rec.endpoint is None


def test_node_record_rejects_bad_did():
    with pytest.raises(ValidationError):
        NodeRecord(
            did="not-a-did",
            node_id="sb-x",
            boxname="x",
            pubkey_wg="Z" * 44,
            mesh_ip="10.10.0.9",
            ddns="x.secubox.in",
        )


def test_node_record_forbids_extra_fields():
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    with pytest.raises(ValidationError):
        NodeRecord(
            did=did,
            node_id="sb-x",
            boxname="x",
            pubkey_wg="Z" * 44,
            mesh_ip="10.10.0.9",
            ddns="x.secubox.in",
            secret="leak",  # extra fields must be rejected (no accidental secret carriage)
        )


# ---------------------------------------------------------------------------
# ConfigBlob — a signed, versioned config distribution entry
# ---------------------------------------------------------------------------

def test_config_blob_constructable_inline():
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    blob = ConfigBlob(
        config_id="cfg-abc123",
        publisher=did,
        scope="yacy",
        version=3,
        content_hash="b" * 64,
        payload={"peer": {"mode": "freeworld"}},
        valid_from=now_rfc3339(),
    )
    assert blob.scope == "yacy"
    assert blob.version == 3
    assert blob.payload == {"peer": {"mode": "freeworld"}}
    assert blob.payload_uri is None
    assert blob.valid_until is None


def test_config_blob_constructable_by_uri():
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    blob = ConfigBlob(
        config_id="cfg-big",
        publisher=did,
        scope="nextcloud",
        version=1,
        content_hash="c" * 64,
        payload_uri="https://gk2.secubox.in/api/v1/annuaire/config/cfg-big/blob",
    )
    assert blob.payload is None
    assert blob.payload_uri.endswith("/blob")


def test_config_blob_version_monotonic_type():
    # version is an int used for last-writer-wins ordering across the mesh.
    _priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    with pytest.raises(ValidationError):
        ConfigBlob(
            config_id="cfg-x",
            publisher=did,
            scope="dns",
            version=-1,  # must be >= 0
            content_hash="d" * 64,
        )


def test_config_blob_rejects_bad_publisher():
    with pytest.raises(ValidationError):
        ConfigBlob(
            config_id="cfg-x",
            publisher="nope",
            scope="dns",
            version=1,
            content_hash="d" * 64,
        )


# ---------------------------------------------------------------------------
# publish_node → directory peer registry
# ---------------------------------------------------------------------------

def test_publish_node_appears_in_registry(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    rec = publish_node(
        tmp_journal, priv, did,
        node_id="sb-aabbccddeeff", boxname="gk2",
        pubkey_wg="W" * 44, mesh_ip="10.10.0.1", ddns="gk2.secubox.in",
        endpoint="82.67.100.75:51822",
    )
    assert rec.sig is not None
    nodes = _get_nodes(tmp_journal)
    assert any(n["did"] == did and n["mesh_ip"] == "10.10.0.1" for n in nodes)


def test_publish_node_latest_supersedes(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    publish_node(tmp_journal, priv, did, node_id="sb-x", boxname="gk2",
                 pubkey_wg="W" * 44, mesh_ip="10.10.0.1", ddns="gk2.secubox.in")
    publish_node(tmp_journal, priv, did, node_id="sb-x", boxname="gk2",
                 pubkey_wg="W" * 44, mesh_ip="10.10.0.7", ddns="gk2.secubox.in")
    nodes = [n for n in _get_nodes(tmp_journal) if n["did"] == did]
    assert len(nodes) == 1 and nodes[0]["mesh_ip"] == "10.10.0.7"


# ---------------------------------------------------------------------------
# publish_config → versioned config distribution
# ---------------------------------------------------------------------------

def test_publish_config_appears(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    blob = publish_config(tmp_journal, priv, did, scope="yacy", version=1,
                          content_hash=_h("v1"), payload={"peer": {"mode": "freeworld"}})
    assert blob.sig is not None
    got = _get_config(tmp_journal, blob.config_id)
    assert got is not None and got["version"] == 1
    assert got["payload"] == {"peer": {"mode": "freeworld"}}


def test_publish_config_higher_version_wins_regardless_of_height(tmp_journal):
    # Last-writer-wins is by VERSION, not by log height — convergence across the
    # mesh requires this (peers ingest in different orders).
    priv, pub, did = _make_member(tmp_journal)
    b1 = publish_config(tmp_journal, priv, did, scope="dns", version=5, content_hash=_h("v5"))
    # a later-appended entry with a LOWER version must NOT win
    publish_config(tmp_journal, priv, did, scope="dns", version=2,
                   content_hash=_h("v2"), config_id=b1.config_id)
    got = _get_config(tmp_journal, b1.config_id)
    assert got["version"] == 5


def test_revoke_config_by_publisher(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    blob = publish_config(tmp_journal, priv, did, scope="dns", version=1, content_hash=_h("v1"))
    revoke_config(tmp_journal, priv, did, blob.config_id)
    assert _get_config(tmp_journal, blob.config_id) is None
    assert all(c["config_id"] != blob.config_id for c in _get_configs(tmp_journal))


def test_revoke_config_by_non_publisher_denied(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    other_priv, other_pub, other_did = _make_member(tmp_journal)
    blob = publish_config(tmp_journal, priv, did, scope="dns", version=1, content_hash=_h("v1"))
    with pytest.raises(PermissionError):
        revoke_config(tmp_journal, other_priv, other_did, blob.config_id)


# ---------------------------------------------------------------------------
# ingest_config → federation (sig-verify-before-append)
# ---------------------------------------------------------------------------

def test_ingest_config_valid_sig(tmp_journal, tmp_path):
    # Producer journal publishes; a separate consumer journal ingests the blob.
    prod = tmp_journal
    priv, pub, did = _make_member(prod)
    blob = publish_config(prod, priv, did, scope="yacy", version=3, content_hash=_h("v3"),
                          payload={"a": 1})

    consumer = Journal(str(tmp_path / "consumer.db"))
    res = ingest_config(consumer, blob, pub.hex())
    assert res["status"] == "ingested"
    assert _get_config(consumer, blob.config_id)["version"] == 3


def test_ingest_config_forged_sig_rejected(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    blob = publish_config(tmp_journal, priv, did, scope="yacy", version=1, content_hash=_h("v1"))
    # tamper: flip the payload after signing
    forged = blob.model_copy(update={"version": 999})
    consumer = Journal(":memory:")
    with pytest.raises(ValueError):
        ingest_config(consumer, forged, pub.hex())


# ---------------------------------------------------------------------------
# can() — config.publish right
# ---------------------------------------------------------------------------

def test_can_config_publish_member_allowed(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    d = can(tmp_journal, did, "config.publish", "mesh.config", domain="fr-chambery")
    assert d.allowed is True


def test_can_config_publish_observed_denied(tmp_journal):
    priv, pub, did = _make_observed(tmp_journal)
    d = can(tmp_journal, did, "config.publish", "mesh.config", domain="fr-chambery")
    assert d.allowed is False


# ---------------------------------------------------------------------------
# export_entries / import_entries — federation gossip (the /log pull core)
# ---------------------------------------------------------------------------

def test_export_import_round_trip(tmp_journal, tmp_path):
    prod = tmp_journal
    priv, pub, did = _make_member(prod)
    publish_node(prod, priv, did, node_id="sb-x", boxname="gk2",
                 pubkey_wg="W" * 44, mesh_ip="10.10.0.1", ddns="gk2.secubox.in")
    publish_config(prod, priv, did, scope="yacy", version=2, content_hash=_h("v2"),
                   payload={"k": "v"})

    consumer = Journal(str(tmp_path / "consumer.db"))
    res = import_entries(consumer, export_entries(prod))
    assert res["ingested"] >= 3 and res["rejected"] == 0

    # State converges: consumer sees the same node + config
    cnodes = _get_nodes(consumer)
    assert any(n["did"] == did and n["mesh_ip"] == "10.10.0.1" for n in cnodes)
    cfg = _get_config(consumer, "cfg-yacy")
    assert cfg is not None and cfg["version"] == 2


def test_import_idempotent(tmp_journal, tmp_path):
    prod = tmp_journal
    priv, pub, did = _make_member(prod)
    publish_config(prod, priv, did, scope="dns", version=1, content_hash=_h("v1"))
    entries = export_entries(prod)

    consumer = Journal(str(tmp_path / "consumer.db"))
    import_entries(consumer, entries)
    res2 = import_entries(consumer, entries)  # second pull: nothing new
    assert res2["ingested"] == 0 and res2["skipped"] == len(entries)
    # no duplicate config
    assert len([c for c in _get_configs(consumer) if c["config_id"] == "cfg-dns"]) == 1


def test_import_rejects_forged_payload(tmp_journal, tmp_path):
    prod = tmp_journal
    priv, pub, did = _make_member(prod)
    publish_config(prod, priv, did, scope="dns", version=1, content_hash=_h("v1"))
    entries = export_entries(prod)
    # tamper the ConfigBlob payload after it was signed
    for e in entries:
        if e["payload_type"] == "ConfigBlob":
            e["payload"]["version"] = 999
    consumer = Journal(str(tmp_path / "consumer.db"))
    res = import_entries(consumer, entries)
    assert res["rejected"] >= 1
    assert _get_config(consumer, "cfg-dns") is None  # forged blob never landed


def test_import_rejects_spoofed_author(tmp_journal, tmp_path):
    prod = tmp_journal
    priv, pub, did = _make_member(prod)
    publish_node(prod, priv, did, node_id="sb-x", boxname="gk2",
                 pubkey_wg="W" * 44, mesh_ip="10.10.0.1", ddns="gk2.secubox.in")
    entries = export_entries(prod)
    # swap in a different pubkey that does NOT hash to the claimed author
    _op, other_pub = generate_keypair()
    for e in entries:
        e["author_pubkey"] = other_pub.hex()
    consumer = Journal(str(tmp_path / "consumer.db"))
    res = import_entries(consumer, entries)
    assert res["ingested"] == 0 and res["rejected"] == len(entries)
