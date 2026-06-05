# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""JA4 / JA4-like TLS ClientHello fingerprint.

Reference: https://github.com/FoxIO-LLC/ja4 (BSD-3)

Phase 2c implementation : compute a deterministic, JA4-style fingerprint
hash from cipher_suites + alpn_protocols + extensions. The output is
12-char hex (truncated SHA256), suitable for matching against external
JA4 databases (custom curation, not the full FoxIO format).

This is NOT the canonical FoxIO JA4 string. It's a deterministic
fingerprint that's stable per-client-stack, so the same iPhone Safari
will always yield the same hash. We can map known hashes to bots,
trackers, malware C2 in Phase 3.
"""
from __future__ import annotations

import hashlib


def _sort_norm(items: list | None) -> str:
    """Sort + join items as canonical comma-separated lowercase string."""
    if not items:
        return ""
    parts = []
    for x in items:
        if isinstance(x, bytes):
            parts.append(x.hex())
        else:
            parts.append(str(x).lower())
    return ",".join(sorted(parts))


def compute_ja4_hash(
    *,
    sni: str | None = None,
    alpn_protocols: list | None = None,
    cipher_suites: list | None = None,
    extensions: list | None = None,
    transport: str = "t",  # 't' for TCP, 'q' for QUIC
    tls_version: str = "13",  # 13 for TLS 1.3, 12 for TLS 1.2
) -> dict:
    """Compute a JA4-style fingerprint dict.

    Returns {
      fingerprint   : 12-char hex hash,
      transport     : t/q,
      tls_version   : 13/12,
      alpn_count    : int,
      cipher_count  : int,
      ext_count     : int,
      sni_present   : bool,
      raw_repr      : compact str repr for debug,
    }
    """
    alpn_str = _sort_norm(alpn_protocols)
    cipher_str = _sort_norm(cipher_suites)
    ext_str = _sort_norm(extensions)
    raw = f"{transport}{tls_version}|alpn={alpn_str}|c={cipher_str}|x={ext_str}"
    h = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return {
        "fingerprint": h,
        "transport": transport,
        "tls_version": tls_version,
        "alpn_count": len(alpn_protocols or []),
        "cipher_count": len(cipher_suites or []),
        "ext_count": len(extensions or []),
        "sni_present": bool(sni),
        "raw_repr": raw[:200],
    }


# Phase 3-ready : map known JA4 hashes to client tags. Empty for now.
KNOWN_JA4_FINGERPRINTS: dict[str, dict] = {
    # "abc123def456": {"label": "iPhone Safari 17.x", "category": "browser", "trust": "high"},
    # "deadbeef0000": {"label": "Tor Browser 14.x", "category": "browser-anon", "trust": "medium"},
}


def lookup_ja4(fingerprint: str) -> dict | None:
    """Return known label for a fingerprint, or None if unknown."""
    return KNOWN_JA4_FINGERPRINTS.get(fingerprint)
