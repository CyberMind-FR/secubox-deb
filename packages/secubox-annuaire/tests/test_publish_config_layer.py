# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_publish_config_layer.py
Pytest coverage for annuaire/verbs.py::publish_config's `layer` parameter
(review finding: the override layer was unreachable end-to-end because
publish_config had no way to publish at anything but the ConfigBlob default
"baseline" layer).

Tests:
  - publish_config(..., layer="override") produces a ConfigBlob whose
    layer == "override", and the journal entry that was appended carries
    the same layer in its payload.
  - publish_config(...) with no `layer` argument still defaults to
    "baseline" (no regression for existing callers).
  - publish_config(..., layer="local") raises ValueError — centers never
    publish the box-local layer to the mesh; the real grant enforcement for
    (scope, layer) ownership still lives entirely in config_router, this is
    just a sanity guard against a layer that structurally cannot apply here.
"""
import hashlib

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import Identity, MemberState, Op
from annuaire.verbs import _get_config, publish_config


@pytest.fixture
def tmp_journal(tmp_path) -> Journal:
    return Journal(str(tmp_path / "test.db"))


def _make_member(journal: Journal):
    """Bootstrap a MEMBER node; returns (priv, pub, did) (mirrors test_directory.py)."""
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


def _h(s: str) -> str:
    return hashlib.blake2b(s.encode(), digest_size=32).hexdigest()


# ---------------------------------------------------------------------------
# layer="override" is now reachable end-to-end
# ---------------------------------------------------------------------------

def test_publish_config_override_layer_roundtrips(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    blob = publish_config(
        tmp_journal, priv, did, scope="firewall", version=1,
        content_hash=_h("v1"), payload={"rules": ["deny all"]}, layer="override",
    )
    assert blob.layer == "override"

    # the journal entry itself (not just the returned ConfigBlob) carries it
    got = _get_config(tmp_journal, blob.config_id)
    assert got is not None
    assert got["layer"] == "override"


# ---------------------------------------------------------------------------
# default stays "baseline" — no regression for existing callers
# ---------------------------------------------------------------------------

def test_publish_config_default_layer_is_baseline(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    blob = publish_config(
        tmp_journal, priv, did, scope="dns", version=1, content_hash=_h("v1"),
    )
    assert blob.layer == "baseline"
    got = _get_config(tmp_journal, blob.config_id)
    assert got["layer"] == "baseline"


# ---------------------------------------------------------------------------
# layer="local" is rejected — centers never publish the box-local layer
# ---------------------------------------------------------------------------

def test_publish_config_local_layer_rejected(tmp_journal):
    priv, pub, did = _make_member(tmp_journal)
    with pytest.raises(ValueError, match="local"):
        publish_config(
            tmp_journal, priv, did, scope="dns", version=1,
            content_hash=_h("v1"), layer="local",
        )
    # nothing was appended for the rejected publish
    assert _get_config(tmp_journal, "cfg-dns") is None
