# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Comprendre une image (#3995) : description ou lecture du texte, par le moteur actif et son projecteur.

- L'image est gardée LOCALEMENT (`$SECUBOX_AI_AGENTS_ETAT/images/`, 0600) et n'est envoyée qu'au moteur, par
  son socket Unix : le service n'a aucun réseau.
- Formats reconnus par leurs octets (PNG, JPEG, WebP), jamais par le nom ni le type déclaré ; 6 Mo au plus.
- Le moteur doit annoncer la vision (`/props` → `modalities.vision`), sinon 409 : aucun texte inventé sur une
  image que le modèle ne voit pas.
"""
from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx

IMAGE_MAX = 6 * 1024 * 1024
TYPES = {b"\x89PNG\r\n\x1a\n": ("png", "image/png"), b"\xff\xd8\xff": ("jpg", "image/jpeg")}
CONSIGNES = {
    "decrire": "Décris cette image en français, précisément et sans rien inventer.",
    "lire": "Recopie fidèlement, en texte brut, tout le texte lisible de cette image. N'invente rien.",
}


def type_reel(octets: bytes) -> tuple[str, str] | None:
    for magie, t in TYPES.items():
        if octets.startswith(magie):
            return t
    if octets[:4] == b"RIFF" and octets[8:12] == b"WEBP":
        return ("webp", "image/webp")
    return None


def decoder(b64: str) -> tuple[bytes, str, str]:
    try:
        octets = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("image illisible (base64)") from exc
    if not octets or len(octets) > IMAGE_MAX:
        raise ValueError("image vide ou trop grande (6 Mo au plus)")
    t = type_reel(octets)
    if t is None:
        raise ValueError("format non reconnu (PNG, JPEG ou WebP)")
    return octets, *t


def garder(etat: Path, octets: bytes, ext: str) -> str:
    d = etat / "images"
    d.mkdir(mode=0o700, exist_ok=True)
    ident = secrets.token_hex(8)
    f = d / f"{ident}.{ext}"
    with open(f, "xb") as sortie:      # jamais d'écrasement
        sortie.write(octets)
    f.chmod(0o600)
    return ident


def vision_disponible(socket: str) -> bool:
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=socket), base_url="http://moteur", timeout=5) as c:
            return bool((c.get("/props").json().get("modalities") or {}).get("vision"))
    except (httpx.HTTPError, ValueError):
        return False


async def flux_image(socket: str, octets: bytes, mime: str, question: str, max_tokens: int,
                     mesure: dict) -> AsyncIterator[str]:
    url = f"data:{mime};base64," + base64.b64encode(octets).decode()
    corps = {"messages": [{"role": "user", "content": [{"type": "text", "text": question},
                                                       {"type": "image_url", "image_url": {"url": url}}]}],
             "max_tokens": max_tokens, "temperature": 0.2, "stream": True}
    debut = time.monotonic()
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=socket), base_url="http://moteur",
                                 timeout=600) as c:
        async with c.stream("POST", "/v1/chat/completions", json=corps) as r:
            if r.status_code != 200:
                raise RuntimeError(f"moteur : HTTP {r.status_code}")
            async for ligne in r.aiter_lines():
                if not ligne.startswith("data: ") or ligne == "data: [DONE]":
                    continue
                m = json.loads(ligne[6:])
                for ch in m.get("choices", []):
                    t = (ch.get("delta") or {}).get("content")
                    if t:
                        mesure.setdefault("premier_s", round(time.monotonic() - debut, 3))
                        mesure["morceaux"] = mesure.get("morceaux", 0) + 1
                        yield t
    mesure["duree_s"] = round(time.monotonic() - debut, 3)
