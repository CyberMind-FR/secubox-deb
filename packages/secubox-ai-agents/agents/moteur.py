# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Moteur d'inférence : LlamaCppEngine d'OpenJarvis, sur le socket Unix de llama-server (#3986).

OpenJarvis parle HTTP ; on lui donne un transport httpx sur socket Unix (`uds=`). Le service n'a aucune
famille d'adresses réseau (unité : `RestrictAddressFamilies=AF_UNIX`) : rien ne peut sortir d'ici.
"""
from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field

import httpx
from openjarvis.core.types import Message
from openjarvis.engine.openai_compat_engines import LlamaCppEngine

SOCKET_DEFAUT = "/run/secubox-ai/moteur.sock"
DELAI_S = 600.0


@dataclass
class Mesure:
    """Ce qu'on mesure d'une génération (ni question, ni réponse)."""
    debut: float = field(default_factory=time.monotonic)
    premier_s: float | None = None
    morceaux: int = 0
    caracteres: int = 0
    duree_s: float = 0.0


class Moteur:
    def __init__(self, socket: str | None = None) -> None:
        self.socket = socket or os.environ.get("SECUBOX_AI_AGENTS_MOTEUR", SOCKET_DEFAUT)
        e = LlamaCppEngine(host="http://moteur")
        e._client.close()
        # Points d'injection prévus par OpenJarvis (`_openai_compat.py` l.69-75) : transport sur socket Unix.
        e._client = httpx.Client(base_url="http://moteur", timeout=DELAI_S,
                                 transport=httpx.HTTPTransport(uds=self.socket))
        e._async_transport = httpx.AsyncHTTPTransport(uds=self.socket)
        self._e = e
        self._modele: str | None = None

    def etat(self) -> dict:
        try:
            ok = self._e.health()
            modeles = self._e.list_models() if ok else []
        except Exception:  # noqa: BLE001 — un moteur absent n'est pas une erreur du service
            ok, modeles = False, []
        if modeles:
            self._modele = modeles[0]
        return {"pret": ok, "modele": os.path.basename(modeles[0]) if modeles else None}

    def modele(self) -> str:
        if not self._modele:
            self.etat()
        if not self._modele:
            raise RuntimeError("moteur indisponible")
        return self._modele

    async def flux(self, messages: Sequence[Message], *, max_tokens: int, temperature: float,
                   mesure: Mesure) -> AsyncIterator[str]:
        async for morceau in self._e.stream(messages, model=self.modele(), max_tokens=max_tokens,
                                            temperature=temperature):
            if mesure.premier_s is None:
                mesure.premier_s = time.monotonic() - mesure.debut
            mesure.morceaux += 1
            mesure.caracteres += len(morceau)
            yield morceau
        mesure.duree_s = time.monotonic() - mesure.debut

    def fermer(self) -> None:
        self._e.close()
