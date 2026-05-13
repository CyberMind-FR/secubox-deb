"""TOTP wrapper: secret, verify (window + replay), backup codes."""
import time
from pathlib import Path

import pyotp
import pytest

from api import totp


def test_generate_secret_is_base32_160bit():
    s = totp.generate_secret()
    assert len(s) == 32
    assert set(s).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))


def test_provisioning_uri_shape():
    uri = totp.provisioning_uri("alice", secret="JBSWY3DPEHPK3PXP", issuer="SecuBox")
    assert uri.startswith("otpauth://totp/")
    assert "alice" in uri
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=SecuBox" in uri


def test_verify_accepts_current_code():
    secret = totp.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok, step = totp.verify(secret, code, last_step=None)
    assert ok
    assert step is not None


def test_verify_rejects_wrong_code():
    secret = totp.generate_secret()
    ok, step = totp.verify(secret, "000000", last_step=None)
    assert ok is False
    assert step is None


def test_verify_refuses_replay_of_same_step():
    secret = totp.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok1, step1 = totp.verify(secret, code, last_step=None)
    assert ok1
    ok2, step2 = totp.verify(secret, code, last_step=step1)
    assert ok2 is False


def test_generate_backup_codes_shape():
    codes = totp.generate_backup_codes(n=10, length=10)
    assert len(codes) == 10
    assert all(len(c) == 10 for c in codes)
    assert all(set(c).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")) for c in codes)
    # Codes are unique
    assert len(set(codes)) == 10


def test_hash_and_verify_backup_code():
    code = "ABCDEFGHIJ"
    h = totp.hash_backup_code(code)
    assert h.startswith("$argon2id$")
    assert totp.verify_backup_code(h, "ABCDEFGHIJ") is True
    assert totp.verify_backup_code(h, "OTHERCODE!") is False
