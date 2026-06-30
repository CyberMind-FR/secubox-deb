# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_config_apply
Replica-side 4R config apply (gondwana P2, #768).
"""
import hashlib

from annuaire.config_apply import apply_blob, apply_pending, load_state


def _h(text):
    return hashlib.blake2b(text.encode(), digest_size=32).hexdigest()


def _blob(scope, version, text, publisher="did:plc:" + "a" * 32):
    return {
        "config_id": f"cfg-{scope}", "publisher": publisher, "scope": scope,
        "version": version, "content_hash": _h(text),
        "payload": {"format": "toml", "text": text},
    }


# ---------------------------------------------------------------------------
# apply_blob — the 4R core
# ---------------------------------------------------------------------------

def test_apply_writes_target_and_keeps_rollback(tmp_path):
    state = {}
    text1 = '[peer]\nmode = "freeworld"\n'
    r = apply_blob(_blob("yacy", 1, text1), str(tmp_path), state)
    assert r["status"] == "applied" and r["version"] == 1
    active = tmp_path / "yacy.toml"
    assert active.read_text() == text1
    assert state["yacy"]["version"] == 1
    # a newer version supersedes and snapshots the previous active to rollback
    text2 = '[peer]\nmode = "intranet"\n'
    r2 = apply_blob(_blob("yacy", 2, text2), str(tmp_path), state)
    assert r2["status"] == "applied"
    assert active.read_text() == text2
    assert (tmp_path / "yacy.toml.sbx-rollback").read_text() == text1


def test_apply_idempotent_by_version(tmp_path):
    state = {}
    text = "a = 1\n"
    apply_blob(_blob("dns", 5, text), str(tmp_path), state)
    r = apply_blob(_blob("dns", 5, text), str(tmp_path), state)  # same version
    assert r["status"] == "skip" and r["reason"] == "version-not-newer"
    older = apply_blob(_blob("dns", 3, "a = 2\n"), str(tmp_path), state)
    assert older["status"] == "skip"
    assert (tmp_path / "dns.toml").read_text() == text  # unchanged


def test_apply_rejects_hash_mismatch_without_touching_active(tmp_path):
    state = {}
    active = tmp_path / "x.toml"
    active.write_text("orig = true\n")
    state["x"] = {"version": 1, "hash": "old"}
    blob = _blob("x", 2, "tampered = 1\n")
    blob["content_hash"] = "deadbeef" * 8  # wrong
    r = apply_blob(blob, str(tmp_path), state)
    assert r["status"] == "reject" and r["reason"] == "hash-mismatch"
    assert active.read_text() == "orig = true\n"  # live config untouched


def test_apply_rejects_unparseable_toml(tmp_path):
    state = {}
    bad = "this is = = not toml ][\n"
    r = apply_blob(_blob("y", 1, bad), str(tmp_path), state)
    assert r["status"] == "reject" and r["reason"] == "unparseable-toml"
    assert not (tmp_path / "y.toml").exists()


def test_apply_rejects_blob_without_inline_text(tmp_path):
    state = {}
    blob = {"scope": "z", "version": 1, "content_hash": "x",
            "payload": {"payload_uri": "https://elsewhere/blob"}}
    r = apply_blob(blob, str(tmp_path), state)
    assert r["status"] == "reject" and r["reason"] == "no-inline-text"


# ---------------------------------------------------------------------------
# apply_pending — allowlist + single-writer gating + state persistence
# ---------------------------------------------------------------------------

def test_apply_pending_allowlist_and_self_skip(tmp_path):
    state_path = str(tmp_path / "applied.json")
    me = "did:plc:" + "f" * 32
    configs = [
        _blob("yacy", 1, "a = 1\n"),                       # allowed, other publisher
        _blob("dns", 1, "b = 2\n"),                        # NOT allowed
        _blob("waf", 1, "c = 3\n", publisher=me),          # allowed scope but self-published
    ]
    results = apply_pending(
        configs, allow_scopes={"yacy", "waf"}, self_did=me,
        target_dir=str(tmp_path), state_path=state_path,
    )
    by = {r["scope"]: r for r in results}
    assert by["yacy"]["status"] == "applied"
    assert by["dns"]["status"] == "skip" and by["dns"]["reason"] == "not-allowed"
    assert by["waf"]["status"] == "skip" and by["waf"]["reason"] == "self-published"
    assert (tmp_path / "yacy.toml").exists()
    assert not (tmp_path / "dns.toml").exists()
    assert not (tmp_path / "waf.toml").exists()
    # state persisted for the applied scope
    assert load_state(state_path)["yacy"]["version"] == 1


def test_apply_pending_wildcard_allows_all(tmp_path):
    state_path = str(tmp_path / "applied.json")
    results = apply_pending(
        [_blob("anything", 1, "k = 1\n")], allow_scopes={"*"}, self_did=None,
        target_dir=str(tmp_path), state_path=state_path,
    )
    assert results[0]["status"] == "applied"
    assert (tmp_path / "anything.toml").read_text() == "k = 1\n"
