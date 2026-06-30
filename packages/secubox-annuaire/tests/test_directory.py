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
import pytest
from pydantic import ValidationError

from annuaire.crypto import did_from_pubkey, generate_keypair
from annuaire.model import (
    ConfigBlob,
    NodeRecord,
    Op,
    now_rfc3339,
)


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
