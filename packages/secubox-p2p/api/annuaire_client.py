# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: annuaire_client

Thin client that calls the local secubox-annuaire API to retrieve the
service catalog (offers list).  Also exposes did_from_pubkey_hex which
mirrors annuaire's self-certifying DID derivation formula exactly:

    did:plc:<sha256(pubkey_raw_bytes).hexdigest()[:32]>

This is the same formula used in:
  - packages/secubox-annuaire/annuaire/crypto.py::did_from_pubkey
  - packages/secubox-identity/api/main.py::generate_did

No extra dependencies: hashlib is stdlib; HTTP calls use urllib from stdlib
so we add zero new Debian deps.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

# Annuaire API base URL — configurable via env for tests/dev.
_ANNUAIRE_BASE = os.environ.get(
    "SECUBOX_ANNUAIRE_URL", "http://127.0.0.1:8730"
)


# ---------------------------------------------------------------------------
# Self-certifying DID derivation (mirrors annuaire/crypto.py::did_from_pubkey)
# ---------------------------------------------------------------------------

def did_from_pubkey_hex(pub_hex: str) -> str:
    """Derive a self-certifying DID from a hex-encoded Ed25519 public key.

    Formula (identical to packages/secubox-annuaire/annuaire/crypto.py):
        did:plc:<sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]>

    Args:
        pub_hex: hex string of the raw 32-byte Ed25519 public key.

    Returns:
        String of the form "did:plc:<32 lowercase hex chars>".
    """
    pub_bytes = bytes.fromhex(pub_hex)
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return f"did:plc:{fingerprint}"


# ---------------------------------------------------------------------------
# Catalog fetch
# ---------------------------------------------------------------------------

def get_catalog(
    base_url: Optional[str] = None,
    timeout: int = 5,
) -> Tuple[List[Dict], Optional[str]]:
    """Fetch the service offer catalog from the local annuaire instance.

    Returns:
        (offers, error) — offers is a list of offer dicts (may be empty);
        error is a human-readable string on failure, None on success.
    """
    url = (base_url or _ANNUAIRE_BASE).rstrip("/") + "/api/v1/annuaire/offers"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            data = json.loads(body)
            # The annuaire API wraps offers in {"offers": [...]} or returns a list directly.
            if isinstance(data, list):
                return data, None
            if isinstance(data, dict):
                return data.get("offers", []), None
            return [], "unexpected catalog shape"
    except urllib.error.URLError as exc:
        return [], f"annuaire unreachable: {exc}"
    except Exception as exc:  # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"
