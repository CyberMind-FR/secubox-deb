# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-annuaire :: threatmesh — bidirectional WAF ban federation (#768)."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import Identity, MemberState, Op
from annuaire.verbs import (
    _get_bans, banned_ips, export_entries, import_entries,
    publish_ban, revoke_ban,
)


@pytest.fixture
def tmp_journal(tmp_path):
    return Journal(str(tmp_path / "test.db"))


def _member(journal):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(),
                     self_cert_digest=hashlib.sha256(pub).hexdigest()[:32], state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    journal.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload,
                   author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub, did


def test_publish_ban_appears_in_union(tmp_journal):
    priv, _pub, did = _member(tmp_journal)
    publish_ban(tmp_journal, priv, did, ip="1.2.3.4", reason="bruteforce", severity="high")
    assert "1.2.3.4" in banned_ips(tmp_journal)
    b = _get_bans(tmp_journal)[0]
    assert b["ip"] == "1.2.3.4" and b["reason"] == "bruteforce" and b["publisher"] == did


def test_union_across_publishers(tmp_journal):
    a_priv, _ap, a = _member(tmp_journal)
    b_priv, _bp, b = _member(tmp_journal)
    publish_ban(tmp_journal, a_priv, a, ip="10.0.0.1")
    publish_ban(tmp_journal, b_priv, b, ip="10.0.0.2")
    publish_ban(tmp_journal, b_priv, b, ip="10.0.0.1")  # same ip, different publisher
    assert banned_ips(tmp_journal) == ["10.0.0.1", "10.0.0.2"]  # union, deduped


def test_revoke_lifts_only_own_ban(tmp_journal):
    a_priv, _ap, a = _member(tmp_journal)
    b_priv, _bp, b = _member(tmp_journal)
    publish_ban(tmp_journal, a_priv, a, ip="9.9.9.9")
    publish_ban(tmp_journal, b_priv, b, ip="9.9.9.9")
    revoke_ban(tmp_journal, a_priv, a, "9.9.9.9")   # A lifts its ban
    assert "9.9.9.9" in banned_ips(tmp_journal)      # B still bans it
    revoke_ban(tmp_journal, b_priv, b, "9.9.9.9")   # B lifts too
    assert "9.9.9.9" not in banned_ips(tmp_journal)


def test_reban_after_revoke_reactivates(tmp_journal):
    priv, _pub, did = _member(tmp_journal)
    publish_ban(tmp_journal, priv, did, ip="5.5.5.5")
    revoke_ban(tmp_journal, priv, did, "5.5.5.5")
    assert "5.5.5.5" not in banned_ips(tmp_journal)
    publish_ban(tmp_journal, priv, did, ip="5.5.5.5")  # re-ban supersedes the revoke
    assert "5.5.5.5" in banned_ips(tmp_journal)


def test_expired_ban_drops_out(tmp_journal):
    priv, _pub, did = _member(tmp_journal)
    publish_ban(tmp_journal, priv, did, ip="7.7.7.7", ttl_s=3600)
    # evaluate "now" 2 hours later → the ban has expired
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    assert all(b["ip"] != "7.7.7.7" for b in _get_bans(tmp_journal, now=future))
    assert "7.7.7.7" in banned_ips(tmp_journal)  # still active at real now


def test_bans_federate_bidirectionally(tmp_journal, tmp_path):
    # node A bans; node B ingests A's log and now enforces A's ban (double-sens).
    a_priv, _ap, a = _member(tmp_journal)
    publish_ban(tmp_journal, a_priv, a, ip="203.0.113.5", reason="scanner")
    consumer = Journal(str(tmp_path / "b.db"))
    import_entries(consumer, export_entries(tmp_journal))
    assert "203.0.113.5" in banned_ips(consumer)


# --------------------------------------------------------------------------- #
# nft ruleset generation (enforcement side)
# --------------------------------------------------------------------------- #

from annuaire.threatmesh import is_ipv4, meshban_ruleset  # noqa: E402


def test_meshban_ruleset_own_table_drops_v4_only():
    rs = meshban_ruleset(["1.2.3.4", "not-an-ip", "10.0.0.9", "dead::beef"])
    assert "table inet secubox_meshban" in rs          # its own table
    assert "ip saddr @banned drop" in rs
    assert "elements = { 1.2.3.4, 10.0.0.9 }" in rs    # v4 only, sorted, deduped
    assert "dead::beef" not in rs and "not-an-ip" not in rs
    assert is_ipv4("1.2.3.4") and not is_ipv4("dead::beef")


def test_meshban_ruleset_empty():
    rs = meshban_ruleset([])
    assert "table inet secubox_meshban" in rs and "elements" not in rs
