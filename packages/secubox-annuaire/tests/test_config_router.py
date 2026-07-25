# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_config_router
Pytest coverage for annuaire/config_router.py::route_config (Task 6).

Tests:
  - A granted, correctly-signed, hash-matching CONFIG_PUBLISH is composed and
    applied to <target_dir>/<scope>.toml.
  - An ungranted publisher's CONFIG_PUBLISH is dropped into "proposals" and
    never applied — the granted layer keeps ruling that scope.
  - A local override file (<local_dir>/<scope>.toml) always wins — highest
    precedence in LAYER_ORDER.
  - A CONFIG_PUBLISH with a tampered/invalid signature is dropped into
    "proposals", even though its publisher holds the grant.

Publisher pubkey resolution note: annuaire.verbs.publish_config() (task 5,
gondwana P1) has no `layer` parameter — ConfigBlob.layer always defaults to
"baseline" through that verb. To publish at other layers (override) these
tests build+sign the ConfigBlob payload directly with `_publish_config_at`,
mirroring publish_config's own signing idiom (sig over canonical_bytes of
the payload without sig/signer_did) and appending it via journal.append() —
exactly what publish_config does internally, just with layer exposed.
"""
import tomllib

from annuaire.config_apply import _blake2b_hex
from annuaire.config_router import route_config
from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import GENESIS_HASH, ConfigBlob, LogEntry, Op
from annuaire.verbs import genesis, grant_issue


def _publish_config_at(journal, priv, did, *, scope, layer, version, text, config_id=None):
    """Sign+append a CONFIG_PUBLISH at an explicit layer (see module docstring)."""
    content_hash = _blake2b_hex(text)
    blob = ConfigBlob(
        config_id=config_id or f"cfg-{scope}-{layer}",
        publisher=did,
        scope=scope,
        version=version,
        content_hash=content_hash,
        layer=layer,
        payload={"text": text},
    )
    full = blob.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(priv, canonical_bytes(payload))
    journal.append(
        op=Op.CONFIG_PUBLISH, payload_type="ConfigBlob", payload=payload,
        author=did, sig=sig_hex,
    )
    return payload, sig_hex


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _actor():
    priv, pub = generate_keypair()
    return priv, pub, did_from_pubkey(pub)


# ---------------------------------------------------------------------------
# Happy path + ungranted proposal + local-wins, all on one journal (brief
# Step 1 scenario).
# ---------------------------------------------------------------------------

def test_route_config_applies_granted_proposes_ungranted_local_wins(tmp_path):
    journal = Journal(str(tmp_path / "log.db"))

    a_priv, a_pub, a_did = _actor()      # granted center for firewall/baseline
    b_priv, b_pub, b_did = _actor()      # NOT granted — attempts firewall/override
    box_priv, box_pub, box_did = _actor()  # local box issuing the grant

    genesis(journal, a_priv)  # Identity entry -> A's pubkey resolvable
    genesis(journal, b_priv)  # Identity entry -> B's pubkey resolvable (sig will verify fine)

    grant_issue(journal, box_priv, box_did, a_did, "firewall", "baseline")

    baseline_text = 'x = 1\n[net]\nb = 1\n'
    _publish_config_at(journal, a_priv, a_did, scope="firewall", layer="baseline",
                        version=1, text=baseline_text)

    # B is correctly signed and hash-correct, but holds NO grant for firewall/override.
    override_text = 'x = 99\n'
    _publish_config_at(journal, b_priv, b_did, scope="firewall", layer="override",
                        version=1, text=override_text)

    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()

    entries = list(journal.iter_entries())
    result = route_config(entries, str(target_dir), self_did=box_did, local_dir=str(local_dir))

    # --- granted baseline applied; ungranted override never composed in ---
    applied_by_scope = {r["scope"]: r for r in result["applied"]}
    assert applied_by_scope["firewall"]["status"] == "applied"
    active = target_dir / "firewall.toml"
    assert active.exists()
    doc = tomllib.loads(active.read_text())
    assert doc["x"] == 1
    assert doc["net"]["b"] == 1

    # --- ungranted push routed to proposals, not applied ---
    assert len(result["proposals"]) == 1
    prop = result["proposals"][0]
    assert prop["publisher"] == b_did
    assert prop["scope"] == "firewall"
    assert prop["layer"] == "override"
    assert prop["reason"] == "no-grant"

    # --- a local layer file always wins (highest LAYER_ORDER precedence) ---
    (local_dir / "firewall.toml").write_text("x = 7\n")
    result2 = route_config(entries, str(target_dir), self_did=box_did, local_dir=str(local_dir))
    doc2 = tomllib.loads(active.read_text())
    assert doc2["x"] == 7
    assert doc2["net"]["b"] == 1  # baseline table survives under the local scalar override
    assert result2["proposals"] == [prop] or result2["proposals"][0]["reason"] == "no-grant"


def test_route_config_local_only_scope_applies_without_any_grant(tmp_path):
    """A scope with no grant at all still routes if a local layer file exists."""
    journal = Journal(str(tmp_path / "log.db"))
    entries = list(journal.iter_entries())  # empty journal — no grants anywhere

    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()
    (local_dir / "standalone.toml").write_text("only = true\n")

    result = route_config(entries, str(target_dir), self_did="did:plc:" + "0" * 32,
                           local_dir=str(local_dir))

    assert result["proposals"] == []
    applied_by_scope = {r["scope"]: r for r in result["applied"]}
    assert applied_by_scope["standalone"]["status"] == "applied"
    doc = tomllib.loads((target_dir / "standalone.toml").read_text())
    assert doc["only"] is True


# ---------------------------------------------------------------------------
# Invalid signature -> proposal, never applied
# ---------------------------------------------------------------------------

def test_route_config_bad_signature_is_proposed_not_applied(tmp_path):
    journal = Journal(str(tmp_path / "log.db"))

    a_priv, a_pub, a_did = _actor()
    box_priv, box_pub, box_did = _actor()

    genesis(journal, a_priv)
    grant_issue(journal, box_priv, box_did, a_did, "dns", "baseline")

    text = "a = 1\n"
    content_hash = _blake2b_hex(text)
    blob = ConfigBlob(
        config_id="cfg-dns", publisher=a_did, scope="dns", version=1,
        content_hash=content_hash, layer="baseline", payload={"text": text},
    )
    full = blob.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}

    # A tampered/garbage signature — well-formed hex, but does not verify.
    tampered_sig = "00" * 64

    fake_entry = LogEntry(
        height=999,
        op=Op.CONFIG_PUBLISH,
        prev_hash=GENESIS_HASH,
        payload_type="ConfigBlob",
        payload=payload,
        author=a_did,
        sig=tampered_sig,
        entry_hash="b" * 64,
    )

    # This entry never went through Journal.append() (which would refuse it at
    # write time) — it represents an untrusted candidate the router itself
    # must independently reject.
    entries = list(journal.iter_entries()) + [fake_entry]

    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()

    result = route_config(entries, str(target_dir), self_did=box_did, local_dir=str(local_dir))

    assert result["applied"] == []
    assert not (target_dir / "dns.toml").exists()
    assert len(result["proposals"]) == 1
    assert result["proposals"][0]["reason"] == "bad-signature"
    assert result["proposals"][0]["publisher"] == a_did
    assert result["proposals"][0]["scope"] == "dns"


def test_route_config_hash_mismatch_is_proposed_not_applied(tmp_path):
    """A granted, VALIDLY-signed CONFIG_PUBLISH whose content_hash does not
    match its own inline text must be rejected — a valid grant + valid
    signature does not excuse a corrupted/miscomputed content_hash.

    The signature is computed over the payload AS PUBLISHED (content_hash
    included), so this must be a genuinely wrong content_hash from the
    publisher's own signing step, not a post-hoc tamper (which would just
    break the signature instead and land in the bad-signature case already
    covered above).
    """
    journal = Journal(str(tmp_path / "log.db"))

    a_priv, a_pub, a_did = _actor()
    box_priv, box_pub, box_did = _actor()

    genesis(journal, a_priv)
    grant_issue(journal, box_priv, box_did, a_did, "waf", "baseline")

    text = "a = 1\n"
    blob = ConfigBlob(
        config_id="cfg-waf", publisher=a_did, scope="waf", version=1,
        content_hash="deadbeef" * 8,  # deliberately wrong for `text` below
        layer="baseline", payload={"text": text},
    )
    full = blob.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(a_priv, canonical_bytes(payload))  # valid sig over the wrong hash
    journal.append(
        op=Op.CONFIG_PUBLISH, payload_type="ConfigBlob", payload=payload,
        author=a_did, sig=sig_hex,
    )

    entries = list(journal.iter_entries())
    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()

    result = route_config(entries, str(target_dir), self_did=box_did, local_dir=str(local_dir))

    assert result["applied"] == []
    assert not (target_dir / "waf.toml").exists()
    assert len(result["proposals"]) == 1
    assert result["proposals"][0]["reason"] == "hash-mismatch"
    assert result["proposals"][0]["publisher"] == a_did
    assert result["proposals"][0]["scope"] == "waf"
