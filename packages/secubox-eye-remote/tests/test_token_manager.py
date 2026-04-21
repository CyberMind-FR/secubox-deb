# packages/secubox-eye-remote/tests/test_token_manager.py
"""Tests for token manager."""
import pytest


def test_generate_device_token():
    """Should generate a secure device token."""
    from core.token_manager import generate_device_token

    token = generate_device_token("eye-001")

    assert token is not None
    assert len(token) >= 32  # At least 32 chars
    assert "eye-001" not in token  # Token should not contain device ID


def test_hash_token():
    """Should hash token with SHA256."""
    from core.token_manager import hash_token

    token = "my-secret-token"
    hashed = hash_token(token)

    assert hashed.startswith("sha256:")
    assert len(hashed) > 10


def test_verify_token():
    """Should verify token against hash."""
    from core.token_manager import hash_token, verify_token

    token = "test-token-12345"
    hashed = hash_token(token)

    assert verify_token(token, hashed) is True
    assert verify_token("wrong-token", hashed) is False


def test_generate_pairing_code():
    """Should generate a 6-char pairing code."""
    from core.token_manager import generate_pairing_code

    code = generate_pairing_code()

    assert len(code) == 6
    assert code.isalnum()
    assert code.isupper()


def test_tokens_are_unique():
    """Generated tokens should be unique."""
    from core.token_manager import generate_device_token

    tokens = [generate_device_token(f"eye-{i}") for i in range(10)]

    assert len(set(tokens)) == 10  # All unique
