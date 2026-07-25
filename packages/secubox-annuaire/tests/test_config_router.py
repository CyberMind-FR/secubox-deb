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

Publisher pubkey resolution note: annuaire.verbs.publish_config() now takes a
`layer` parameter (see tests/test_publish_config_layer.py), but these tests
still build+sign the ConfigBlob payload directly with `_publish_config_at` to
keep full control over config_id/version/content_hash combinations exercised
here — mirroring publish_config's own signing idiom (sig over
canonical_bytes of the payload without sig/signer_did) and appending it via
journal.append() — exactly what publish_config does internally.
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


# ---------------------------------------------------------------------------
# apply=False — read-only dry pass (Task 8: GET /centers/proposals +
# GET /centers/effective/{scope} in api/main.py never write to disk).
# ---------------------------------------------------------------------------

def test_route_config_apply_false_writes_nothing(tmp_path):
    """apply=False must never touch target_dir, yet still surface the
    composed text it WOULD have written and the exact same proposals a real
    (apply=True) route would produce."""
    journal = Journal(str(tmp_path / "log.db"))

    a_priv, a_pub, a_did = _actor()
    b_priv, b_pub, b_did = _actor()
    box_priv, box_pub, box_did = _actor()

    genesis(journal, a_priv)
    genesis(journal, b_priv)
    grant_issue(journal, box_priv, box_did, a_did, "firewall", "baseline")

    baseline_text = 'x = 1\n'
    _publish_config_at(journal, a_priv, a_did, scope="firewall", layer="baseline",
                        version=1, text=baseline_text)
    # Ungranted — always a proposal, apply or not.
    _publish_config_at(journal, b_priv, b_did, scope="firewall", layer="override",
                        version=1, text="x = 99\n")

    entries = list(journal.iter_entries())
    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()

    dry = route_config(entries, str(target_dir), self_did=box_did,
                        local_dir=str(local_dir), apply=False)

    # Nothing was written to target_dir at all.
    assert not target_dir.exists()

    # The composed text is still surfaced, best-effort, for a read-only preview.
    applied_by_scope = {r["scope"]: r for r in dry["applied"]}
    assert applied_by_scope["firewall"]["status"] == "would-apply"
    doc = tomllib.loads(applied_by_scope["firewall"]["text"])
    assert doc["x"] == 1

    # Proposals are identical to a real (apply=True) route.
    wet = route_config(entries, str(target_dir), self_did=box_did,
                        local_dir=str(local_dir), apply=True)
    assert dry["proposals"] == wet["proposals"]
    assert len(dry["proposals"]) == 1
    assert dry["proposals"][0]["reason"] == "no-grant"

    # The apply=True call above DID write — confirms apply=False's silence
    # above was not simply because writing is always a no-op for this fixture.
    assert (target_dir / "firewall.toml").exists()


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


# ---------------------------------------------------------------------------
# Sovereignty guard — a GRANT_ISSUE federated in from a mesh peer (issued_by
# != self_did) must never be honored as this box's own delegated authority
# (CRITICAL finding, souveraineté rompue). This test MUST FAIL before the
# grants.py/config_router.py self_did filter and PASS after.
# ---------------------------------------------------------------------------

def test_route_config_foreign_issued_grant_is_not_honored_sovereignty(tmp_path):
    """A well-formed, plausible-looking GRANT_ISSUE that synced in from the
    mesh (dir_sync import_entries) — issued_by a PEER box, not this one —
    must not confer delegated authority here. Without the sovereignty
    filter, X's correctly-signed, hash-correct CONFIG_PUBLISH would be
    applied to firewall.toml; with it, X holds no grant THIS box ever
    issued, so the push is a proposal (reason "no-grant") and nothing is
    written to disk.
    """
    journal = Journal(str(tmp_path / "log.db"))

    x_priv, x_pub, x_did = _actor()        # center X — receives the FOREIGN grant
    _box_priv, _box_pub, box_did = _actor()  # this box — the sovereign local identity
    pair_did = "did:plc:" + "f" * 32       # a mesh peer box — NOT this box

    genesis(journal, x_priv)  # X's pubkey resolvable for CONFIG_PUBLISH sig check

    # A GRANT_ISSUE as it would land here via mesh federation: naming X as
    # owner of firewall/baseline, but issued_by a PEER box's did, not ours.
    # It never goes through annuaire.verbs.grant_issue() (which always sets
    # issued_by=box_did of the signer) — it represents an entry synced in
    # from elsewhere, exactly like the tampered CONFIG_PUBLISH LogEntry built
    # by hand above.
    foreign_grant_entry = LogEntry(
        height=0,
        op=Op.GRANT_ISSUE,
        prev_hash=GENESIS_HASH,
        payload_type="Grant",
        payload={
            "grant_id": "g-foreign-1",
            "center_did": x_did,
            "capability": "config",
            "scope": "firewall",
            "layer": "baseline",
            "issued_by": pair_did,
        },
        author=pair_did,
        sig="deadbeef" * 8,
        entry_hash="c" * 64,
    )

    # X, believing (correctly, on the PEER's own journal) that it holds the
    # grant, signs and publishes firewall/baseline exactly as a legitimately
    # granted center would — correct signature, correct content_hash.
    text = "x = 1\n"
    _publish_config_at(journal, x_priv, x_did, scope="firewall", layer="baseline",
                        version=1, text=text)

    entries = list(journal.iter_entries()) + [foreign_grant_entry]

    target_dir = tmp_path / "target"
    local_dir = tmp_path / "local"
    local_dir.mkdir()

    result = route_config(entries, str(target_dir), self_did=box_did, local_dir=str(local_dir))

    assert result["applied"] == []
    assert not (target_dir / "firewall.toml").exists()
    assert len(result["proposals"]) == 1
    assert result["proposals"][0]["reason"] == "no-grant"
    assert result["proposals"][0]["publisher"] == x_did
    assert result["proposals"][0]["scope"] == "firewall"

    from annuaire import grants  # noqa: PLC0415
    assert grants.owner(entries, "firewall", "baseline", self_did=box_did) is None
