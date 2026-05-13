# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for api/webhook.py — HMAC, dispatcher, filters, lock."""
import hashlib
import hmac

import pytest

from webhook import verify_signature


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_verify_signature_valid():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)
    assert verify_signature(secret, body, sig) is True


def test_verify_signature_wrong_secret_fails():
    body = b'{"hello": "world"}'
    sig = _sign(b"wrong-secret-padded-to-32-bytes!", body)
    assert verify_signature(b"correct-secret-padded-to-32!!!", body, sig) is False


def test_verify_signature_truncated_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)[:-2]
    assert verify_signature(secret, body, sig) is False


def test_verify_signature_empty_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    assert verify_signature(secret, body, "") is False


def test_load_secret_reads_file(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"abc123\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s = webhook.load_secret(p)
    assert s == b"abc123"


def test_load_secret_missing_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        webhook.load_secret(p)


def test_load_secret_empty_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "empty"
    p.write_bytes(b"")
    with pytest.raises(ValueError):
        webhook.load_secret(p)


def test_load_secret_caches(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"first\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s1 = webhook.load_secret(p)
    p.write_bytes(b"changed\n")
    s2 = webhook.load_secret(p)
    assert s1 == s2 == b"first"  # cache wins
