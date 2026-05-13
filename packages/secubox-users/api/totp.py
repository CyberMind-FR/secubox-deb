"""RFC 6238 TOTP wrapper + backup-code generator (argon2id-hashed)."""
from __future__ import annotations

import secrets
from typing import List, Optional, Tuple

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

BACKUP_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # base32


def generate_secret() -> str:
    """Return a fresh 160-bit base32 secret (32 chars)."""
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str, issuer: str = "SecuBox") -> str:
    """Return an `otpauth://` URI suitable for QR encoding."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify(secret: str, code: str, last_step: Optional[int]) -> Tuple[bool, Optional[int]]:
    """Verify a TOTP code with ±1 window. Refuse replay of `last_step`.

    Returns (ok, step) — `step` is the accepted step counter, or None on failure.
    """
    if not code or not code.isdigit() or len(code) != 6:
        return False, None
    totp_obj = pyotp.TOTP(secret)
    now = int(__import__("time").time())
    step_size = 30
    current = now // step_size
    for delta in (-1, 0, 1):
        step = current + delta
        candidate = totp_obj.at(step * step_size)
        if secrets.compare_digest(candidate, code):
            if last_step is not None and step <= last_step:
                return False, None
            return True, step
    return False, None


def generate_backup_codes(n: int = 10, length: int = 10) -> List[str]:
    """Return `n` unique base32 codes of `length` chars each."""
    codes: set = set()
    while len(codes) < n:
        codes.add("".join(secrets.choice(BACKUP_ALPHABET) for _ in range(length)))
    return sorted(codes)


def hash_backup_code(code: str) -> str:
    """Return an argon2id PHC string for a backup code."""
    return _HASHER.hash(code)


def verify_backup_code(hash_: str, code: str) -> bool:
    """Return True if `code` matches `hash_`."""
    try:
        return _HASHER.verify(hash_, code)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
