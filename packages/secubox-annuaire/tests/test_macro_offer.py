# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_macro_offer.py
Pytest coverage for ServiceOffer.macro descriptor (Task 1: M2 macro subsystem).

Tests:
  - MacroDescriptor.kind pattern validation.
  - ServiceOffer.macro defaults to None.
  - Macro round-trips through offer_service and federation (self-cert ingest).
"""
import tempfile
import pytest
from annuaire.model import ServiceOffer, MacroDescriptor
from annuaire.log import Journal
from annuaire.crypto import generate_keypair
from annuaire.verbs import genesis, offer_service, _get_offers, ingest_offer

DID = "did:plc:" + "a" * 32


def test_macro_descriptor_validates_kind():
    MacroDescriptor(kind="tor-exit", params={"socks_port": 9050})
    with pytest.raises(Exception):
        MacroDescriptor(kind="../evil", params={})
    with pytest.raises(Exception):
        MacroDescriptor(kind="Tor Exit", params={})


def test_offer_without_macro_still_valid():
    o = ServiceOffer(service_id="s" * 64, provider=DID, name="n", kind="api",
                     endpoint="/x", sig="0" * 128, signer_did=DID)
    assert o.macro is None


def test_macro_round_trips_through_offer_and_federation():
    ja = Journal(tempfile.mktemp(suffix=".db"))
    pa, pub = generate_keypair()
    ida = genesis(ja, pa)
    offer_service(ja, pa, ida.did, name="Tor exit", kind="tor-exit",
                  endpoint="http://10.10.0.1/tor", approval_mode="auto",
                  macro={"kind": "tor-exit", "params": {"socks_port": 9050}})
    wire = _get_offers(ja)[0]
    assert wire["macro"]["kind"] == "tor-exit"
    assert wire["macro"]["params"]["socks_port"] == 9050
    # federate into a second journal (self-cert), macro preserved
    jb = Journal(tempfile.mktemp(suffix=".db"))
    genesis(jb, generate_keypair()[0])
    allowed = set(ServiceOffer.model_fields)
    offer = ServiceOffer(**{k: v for k, v in wire.items() if k in allowed})
    ingest_offer(jb, offer, wire["provider_pubkey"])
    assert _get_offers(jb)[0]["macro"]["kind"] == "tor-exit"
