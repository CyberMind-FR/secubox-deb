# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — l'enveloppe inter-box (#1736)

Ce que la box signe n'est JAMAIS une donnée arbitraire (#1417, S8 : un point
de signature ouvert fait de l'identité un oracle). C'est toujours cette
enveloppe, qui dit qui parle, à qui, quand, et une seule fois :

    {v, de, a, emis, nonce, objet, contenu}

`a` fait qu'une enveloppe signée pour gk3 ne vaut rien chez gk4 ; `emis` et
`nonce` qu'on ne la rejoue pas. Sérialisation canonique (clés triées, pas
d'espace, pas de flottant) : la même que l'annuaire.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Optional

VERSION = 1
DERIVE_S = 900               # ±15 min, comme les preuves de la fédération
MAX_OBJET = 200
MAX_CONTENU = 128 * 1024
_DID = re.compile(r"^did:plc:[0-9a-f]{32}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")


class EnveloppeInvalide(ValueError):
    pass


def construire(de: str, a: str, objet: str, contenu: str,
               maintenant: Optional[float] = None, nonce: Optional[str] = None) -> bytes:
    e = {"v": VERSION, "de": de, "a": a,
         "emis": int(time.time() if maintenant is None else maintenant),
         "nonce": nonce or secrets.token_hex(16), "objet": objet, "contenu": contenu}
    valider(e)
    return json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def valider(e: dict) -> dict:
    if not isinstance(e, dict) or set(e) != {"v", "de", "a", "emis", "nonce", "objet", "contenu"}:
        raise EnveloppeInvalide("champs de l'enveloppe")
    if e["v"] != VERSION:
        raise EnveloppeInvalide("version")
    if not (_DID.match(str(e["de"])) and _DID.match(str(e["a"]))) or e["de"] == e["a"]:
        raise EnveloppeInvalide("expéditeur ou destinataire")
    if not isinstance(e["emis"], int) or isinstance(e["emis"], bool) or e["emis"] < 0:
        raise EnveloppeInvalide("date d'émission")
    if not _NONCE.match(str(e["nonce"])):
        raise EnveloppeInvalide("nonce")
    if not isinstance(e["objet"], str) or len(e["objet"]) > MAX_OBJET:
        raise EnveloppeInvalide("objet")
    if not isinstance(e["contenu"], str) or len(e["contenu"].encode()) > MAX_CONTENU:
        raise EnveloppeInvalide("contenu")
    return e


def lire(octets: bytes, maintenant: Optional[float] = None) -> dict:
    """L'enveloppe déchiffrée, validée et FRAÎCHE."""
    try:
        e = json.loads(octets.decode())
    except (UnicodeDecodeError, ValueError):
        raise EnveloppeInvalide("illisible")
    valider(e)
    t = time.time() if maintenant is None else maintenant
    if abs(t - e["emis"]) > DERIVE_S:
        raise EnveloppeInvalide("hors de la fenêtre de fraîcheur")
    return e
