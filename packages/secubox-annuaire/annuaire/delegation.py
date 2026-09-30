# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.delegation — assertion d'entrée déléguée (#1720)

Le CENTRE d'une assistance (gk2) signe, avec la clé de son nœud, une assertion
courte qui dit : « mon compte X entre chez la box B, au titre de la session
d'assistance S ». La BOX la vérifie avec la clé publiée du centre et n'ouvre
rien si elle n'a pas elle-même consenti (annuaire.assist.delegation_active).

L'assertion ne porte AUCUN pouvoir par elle-même : c'est le consentement signé
par la box, dans son propre journal, qui en donne. Elle ne sert qu'à prouver
qui frappe à la porte, et une seule fois (nonce, 60 s).
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import time
from typing import Any, Callable, Dict, Optional

from .crypto import canonical_bytes, did_from_pubkey, public_from_private, sign, verify

DUREE_S = 60
DERIVE_S = 30          # tolérance d'horloge entre nœuds
_COMPTE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_DID = re.compile(r"^did:plc:[0-9a-f]{32}$")


class Refus(ValueError):
    """Assertion refusée ; le message dit pourquoi, sans rien de secret."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _deb64(texte: str) -> bytes:
    return base64.urlsafe_b64decode(texte + "=" * (-len(texte) % 4))


def emettre(priv: bytes, box_did: str, compte: str, session_id: str,
            now: Optional[float] = None) -> str:
    """Assertion signée par le centre (clé privée du nœud `priv`)."""
    if not _COMPTE.match(compte or ""):
        raise Refus("compte d'aide invalide")
    t = int(now if now is not None else time.time())
    p = {"v": 1, "box_did": box_did,
         "center_did": did_from_pubkey(public_from_private(priv)),
         "compte": compte, "session_id": session_id,
         "iat": t, "exp": t + DUREE_S, "nonce": secrets.token_hex(16)}
    corps = {"p": p, "sig": sign(priv, canonical_bytes(p))}
    return _b64(json.dumps(corps, separators=(",", ":")).encode())


def verifier(jeton: str, *, self_did: str,
             pubkey_de: Callable[[str], Optional[str]],
             now: Optional[float] = None) -> Dict[str, Any]:
    """Payload de l'assertion si elle est authentique, fraîche et pour CETTE box.

    `pubkey_de(did)` rend la clé publique hex publiée pour ce DID (fiche
    Identity du journal), ou None. Lève Refus sinon."""
    try:
        corps = json.loads(_deb64(jeton or ""))
        p, sig = corps["p"], corps["sig"]
    except (ValueError, KeyError, TypeError):
        raise Refus("assertion illisible")
    if not isinstance(p, dict) or p.get("v") != 1:
        raise Refus("version d'assertion inconnue")
    if p.get("box_did") != self_did:
        raise Refus("assertion destinée à une autre box")
    centre = p.get("center_did") or ""
    if not _DID.match(centre) or centre == self_did:
        raise Refus("centre invalide")
    if not _COMPTE.match(str(p.get("compte") or "")):
        raise Refus("compte d'aide invalide")
    t = time.time() if now is None else now
    try:
        iat, exp = int(p["iat"]), int(p["exp"])
    except (KeyError, TypeError, ValueError):
        raise Refus("dates absentes")
    if exp - iat > 2 * DUREE_S or iat > t + DERIVE_S or exp < t - DERIVE_S:
        raise Refus("assertion échue ou pas encore valable")
    if not re.fullmatch(r"[0-9a-f]{32}", str(p.get("nonce") or "")):
        raise Refus("nonce invalide")
    pub = pubkey_de(centre)
    if not pub:
        raise Refus("centre inconnu de l'annuaire (identité non publiée)")
    try:
        if did_from_pubkey(bytes.fromhex(pub)) != centre:
            raise Refus("clé publiée incohérente avec le centre")
    except ValueError:
        raise Refus("clé publiée illisible")
    if not verify(pub, canonical_bytes(p), str(sig)):
        raise Refus("signature invalide")
    return p
