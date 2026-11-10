# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Vérification des objets signés reçus de l'annuaire (#3647, MIRRORNET_SECURITY.md § 2) : rien n'est cru sur parole.

Mêmes règles que l'annuaire (`annuaire/crypto.py`), réécrites ici sans l'importer (MirrorNet ne dépend pas du code de
l'annuaire) : sérialisation canonique JSON (clés triées, sans espaces, ASCII), did:plc = « did:plc: » + sha256(clé)[:32],
signature Ed25519 sur la charge canonique.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DID = re.compile(r"^did:plc:[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


def canonical_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def did_de_cle(pub_hex: str) -> str:
    return "did:plc:" + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def entree_valide(e: Any) -> bool:
    """Entrée exportée {op, payload, author, author_pubkey, sig} : liaison did ↔ clé ET signature valide."""
    if not isinstance(e, dict):
        return False
    auteur, cle, sig, charge = e.get("author"), e.get("author_pubkey"), e.get("sig"), e.get("payload")
    if not (isinstance(auteur, str) and DID.match(auteur) and isinstance(cle, str) and _HEX64.match(cle)
            and isinstance(sig, str) and _HEX128.match(sig) and isinstance(charge, dict)
            and isinstance(e.get("op"), str)):
        return False
    if did_de_cle(cle) != auteur:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(cle)).verify(bytes.fromhex(sig), canonical_bytes(charge))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
