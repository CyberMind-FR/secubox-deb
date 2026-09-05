# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_federation.py

Trustless cross-node service federation (#766).

The federation contract: a node can ingest a remote service offer WITHOUT any
prior trust in the provider, because did:plc is self-certifying
(did == sha256(pubkey)[:32]). The offer published at GET /services carries the
provider's pubkey + signature; the consumer verifies BOTH that the signature is
valid AND that the pubkey hashes to the claimed provider DID. Either check
failing rejects the offer.

Tests:
  - genesis() mints a founding MEMBER, self-certifying, idempotent.
  - _get_offers enriches each offer with sig + signer_did + provider_pubkey.
  - Full round-trip: serialize A's offer dict → reconstruct ServiceOffer from
    model fields only → ingest on B (A unknown to B beforehand) → succeeds.
  - Forgery: a different keypair's pubkey for A's DID → self-certification
    failure (rejected before the signature is even checked).
  - Tamper: correct pubkey but mutated payload → signature failure.
"""
import tempfile

import pytest

from annuaire.crypto import (
    did_from_pubkey,
    generate_keypair,
    public_from_private,
)
from annuaire.log import Journal
from annuaire.model import ServiceOffer
from annuaire.verbs import (
    _get_offers,
    _is_non_revoked_member,
    genesis,
    ingest_offer,
    offer_service,
)

OFFER_MODEL_FIELDS = set(ServiceOffer.model_fields)


@pytest.fixture
def journal_a(tmp_path):
    return Journal(str(tmp_path / "a.db"))


@pytest.fixture
def journal_b(tmp_path):
    return Journal(str(tmp_path / "b.db"))


def _reconstruct_from_wire(raw: dict) -> ServiceOffer:
    """Mimic the pull path: drop transport-only keys (provider_pubkey) before
    rebuilding the ServiceOffer, which is extra=forbid."""
    return ServiceOffer(**{k: v for k, v in raw.items() if k in OFFER_MODEL_FIELDS})


# --------------------------------------------------------------------------- #
# genesis
# --------------------------------------------------------------------------- #

def test_genesis_mints_self_certifying_member(journal_a):
    priv, pub = generate_keypair()
    ident = genesis(journal_a, priv)
    assert ident.did == did_from_pubkey(pub)
    assert ident.self_cert_digest == ident.did.split(":")[-1]
    assert ident.pubkey == pub.hex()
    assert _is_non_revoked_member(journal_a, ident.did), "genesis must confer MEMBER"
    # founder is grafted by no one
    assert ident.invited_by in (None, "", [])


def test_genesis_is_idempotent(journal_a):
    priv, _ = generate_keypair()
    a = genesis(journal_a, priv)
    height_after_first = journal_a.tip().height
    b = genesis(journal_a, priv)
    assert a.did == b.did
    assert journal_a.tip().height == height_after_first, "second genesis must not fork the chain"


# --------------------------------------------------------------------------- #
# offer enrichment
# --------------------------------------------------------------------------- #

def test_get_offers_carries_sig_signer_and_pubkey(journal_a):
    priv, pub = generate_keypair()
    ident = genesis(journal_a, priv)
    offer_service(journal_a, priv, ident.did, name="WAF mirror", kind="module",
                  endpoint="http://10.10.0.1/api/v1/waf", approval_mode="auto")
    offers = _get_offers(journal_a)
    assert len(offers) == 1
    o = offers[0]
    assert o["sig"], "offer must carry its signature for federation"
    assert o["signer_did"] == ident.did
    assert o["provider_pubkey"] == pub.hex(), "offer must carry the provider pubkey"
    # the carried pubkey must hash to the provider DID (self-certifying)
    assert did_from_pubkey(bytes.fromhex(o["provider_pubkey"])) == o["provider"]


# --------------------------------------------------------------------------- #
# trustless round-trip pull
# --------------------------------------------------------------------------- #

def test_trustless_pull_round_trip(journal_a, journal_b):
    # A: founder publishes an offer
    priv_a, pub_a = generate_keypair()
    id_a = genesis(journal_a, priv_a)
    offer_service(journal_a, priv_a, id_a.did, name="Threatmesh decisions", kind="api",
                  endpoint="http://10.10.0.1/api/v1/threatmesh", approval_mode="auto")
    wire = _get_offers(journal_a)[0]   # what GET /services would emit

    # B: a different founder — A is unknown to B beforehand
    genesis(journal_b, generate_keypair()[0])
    assert not _get_offers(journal_b)

    offer_obj = _reconstruct_from_wire(wire)
    res = ingest_offer(journal_b, offer_obj, wire["provider_pubkey"])
    assert res["status"] == "ingested"

    b_offers = _get_offers(journal_b)
    assert len(b_offers) == 1
    assert b_offers[0]["service_id"] == wire["service_id"]
    assert b_offers[0]["provider"] == id_a.did


# --------------------------------------------------------------------------- #
# attacks
# --------------------------------------------------------------------------- #

def test_forged_provider_pubkey_rejected(journal_a, journal_b):
    """An attacker presents their OWN keypair while claiming A's DID. The sig is
    valid for the attacker's key, but the key does not hash to A's DID, so
    self-certification fails first."""
    priv_a, _ = generate_keypair()
    id_a = genesis(journal_a, priv_a)
    offer_service(journal_a, priv_a, id_a.did, name="x", kind="api", endpoint="/x")
    wire = _get_offers(journal_a)[0]

    genesis(journal_b, generate_keypair()[0])
    _, attacker_pub = generate_keypair()
    offer_obj = _reconstruct_from_wire(wire)
    with pytest.raises(ValueError, match="self-certification failed"):
        ingest_offer(journal_b, offer_obj, attacker_pub.hex())
    assert not _get_offers(journal_b), "forged offer must not be ingested"


def test_tampered_payload_rejected(journal_a, journal_b):
    """Correct pubkey (hashes to A's DID) but the payload is mutated after
    signing → the signature no longer matches → rejected."""
    priv_a, pub_a = generate_keypair()
    id_a = genesis(journal_a, priv_a)
    offer_service(journal_a, priv_a, id_a.did, name="orig", kind="api", endpoint="/x")
    wire = _get_offers(journal_a)[0]

    genesis(journal_b, generate_keypair()[0])
    tampered = dict(wire)
    tampered["endpoint"] = "/evil"   # mutate a signed field
    offer_obj = _reconstruct_from_wire(tampered)
    with pytest.raises(ValueError, match="signature verification failed"):
        ingest_offer(journal_b, offer_obj, pub_a.hex())
    assert not _get_offers(journal_b)


def test_pubkey_hex_garbage_rejected(journal_a, journal_b):
    priv_a, _ = generate_keypair()
    id_a = genesis(journal_a, priv_a)
    offer_service(journal_a, priv_a, id_a.did, name="x", kind="api", endpoint="/x")
    wire = _get_offers(journal_a)[0]
    genesis(journal_b, generate_keypair()[0])
    offer_obj = _reconstruct_from_wire(wire)
    with pytest.raises(ValueError):
        ingest_offer(journal_b, offer_obj, "not-hex-zzz")
