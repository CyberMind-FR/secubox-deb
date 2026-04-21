"""
SecuBox Eye Remote — Token Manager
Handles device token generation and validation.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import hashlib
import secrets
import string


def generate_device_token(device_id: str) -> str:
    """
    Generate a secure device token.

    Args:
        device_id: Device identifier (not included in token)

    Returns:
        Random 48-char hex token
    """
    # Use secrets for cryptographic randomness
    return secrets.token_hex(24)


def hash_token(token: str) -> str:
    """
    Hash a token with SHA256.

    Args:
        token: Plain text token

    Returns:
        Hash string in format "sha256:<hex>"
    """
    h = hashlib.sha256(token.encode()).hexdigest()
    return f"sha256:{h}"


def verify_token(token: str, token_hash: str) -> bool:
    """
    Verify a token against its hash.

    Args:
        token: Plain text token
        token_hash: Hash to verify against

    Returns:
        True if token matches hash
    """
    expected = hash_token(token)
    return secrets.compare_digest(expected, token_hash)


def generate_pairing_code() -> str:
    """
    Generate a 6-character pairing code.

    Returns:
        Random 6-char uppercase alphanumeric code
    """
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(6))


def generate_qr_token(device_id: str, secubox_host: str) -> tuple[str, str]:
    """
    Generate token and QR code URL for pairing.

    Args:
        device_id: Device identifier
        secubox_host: SecuBox hostname or IP

    Returns:
        Tuple of (token, qr_url)
    """
    token = generate_device_token(device_id)
    qr_url = f"http://{secubox_host}:8000/api/v1/eye-remote/pair?device_id={device_id}&token={token}"
    return token, qr_url
