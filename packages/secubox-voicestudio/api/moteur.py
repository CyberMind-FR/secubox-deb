# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: VoiceStudio — client du moteur (contrat audio compatible OpenAI).

VoiceStudio est sous AGPL-3.0 (poids par défaut CC-BY-NC) : il reste un PROCESSUS SÉPARÉ,
dans son propre LXC, joint par le réseau. Aucun import, aucun lien de code.

On passe par le mandataire de l'hôte (127.0.0.1:3900) et non par l'IP du LXC : en mode « à la
demande » c'est lui qui réveille le conteneur, le premier appel attend alors le démarrage à froid.

Ce client ne fabrique jamais de réponse : un moteur absent est dit absent (MoteurIndisponible).
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

import httpx

log = logging.getLogger("voicestudio.moteur")

FORMATS = {"wav": "audio/wav", "mp3": "audio/mpeg", "opus": "audio/ogg"}


class MoteurIndisponible(RuntimeError):
    """Le moteur ne peut pas répondre ; le message est destiné à l'opérateur ET à l'usager."""


def _normaliser_voix(brut) -> list[dict]:
    """Le contrat varie selon les versions : liste, {"voices": [...]} ou {"data": [...]}, éléments
    chaîne ou objets. On rend toujours [{id, nom}] — sans inventer une voix absente."""
    if isinstance(brut, dict):
        brut = brut.get("voices", brut.get("data", []))
    voix: list[dict] = []
    for v in brut if isinstance(brut, list) else []:
        if isinstance(v, str):
            voix.append({"id": v, "nom": v})
        elif isinstance(v, dict):
            ident = v.get("id") or v.get("voice_id") or v.get("name")
            if not ident:
                continue
            entree = {"id": str(ident), "nom": str(v.get("name") or v.get("label") or ident)}
            if v.get("language"):
                entree["langue"] = str(v["language"])
            voix.append(entree)
    return voix


class Moteur:
    def __init__(self, url: str, cle: Callable[[], Awaitable[str]], delai_s: int = 120,
                 transport: httpx.AsyncBaseTransport | None = None, url_rapide: str = "") -> None:
        self.url = url.rstrip("/")
        self.url_rapide = url_rapide.rstrip("/")
        self._cle = cle
        self.delai_s = delai_s
        self._transport = transport          # tests seulement

    async def _entetes(self) -> dict:
        cle = await self._cle()
        return {"Authorization": f"Bearer {cle}"} if cle else {}

    async def _appel(self, methode: str, chemin: str, delai: float | None = None, **kw) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=delai or self.delai_s, transport=self._transport) as cli:
                r = await cli.request(methode, self.url + chemin, headers=await self._entetes(), **kw)
        except (httpx.HTTPError, OSError) as e:
            raise MoteurIndisponible(f"moteur injoignable ({type(e).__name__})") from e
        if r.status_code == 401:
            # Clé périmée (renouvelée entre-temps) : la prochaine lecture de la clé la reprendra.
            raise MoteurIndisponible("clé du moteur refusée — renouvelée ? réessayez")
        if r.status_code >= 400:
            raise MoteurIndisponible(f"le moteur a répondu HTTP {r.status_code}")
        return r

    async def voix(self) -> list[dict]:
        r = await self._appel("GET", "/v1/audio/voices", delai=15)
        try:
            return _normaliser_voix(r.json())
        except ValueError as e:
            raise MoteurIndisponible("liste de voix illisible") from e

    async def dire(self, texte: str, voix: str, format_: str = "mp3") -> bytes:
        charge = {"model": "tts-1", "input": texte, "response_format": format_}
        if voix:
            charge["voice"] = voix
        return (await self._appel("POST", "/v1/audio/speech", json=charge)).content

    async def dire_rapide(self, texte: str, format_: str = "mp3") -> bytes:
        """La voix rapide (Piper français, dans le LXC) : moins d'une seconde. Contrat identique au moteur.
        Le moteur principal est d'abord sondé par le mandataire : en mode « à la demande » c'est lui qui réveille le
        conteneur, et la voix rapide vit dedans. Toute défaillance lève MoteurIndisponible — l'appelant retombe alors
        sur le grand modèle, il ne fabrique rien."""
        if not self.url_rapide:
            raise MoteurIndisponible("voix rapide non configurée")
        await self._appel("GET", "/health", delai=60)
        charge = {"input": texte, "response_format": format_}
        try:
            async with httpx.AsyncClient(timeout=30, transport=self._transport) as cli:
                r = await cli.post(self.url_rapide + "/v1/audio/speech", json=charge, headers=await self._entetes())
        except (httpx.HTTPError, OSError) as e:
            raise MoteurIndisponible(f"voix rapide injoignable ({type(e).__name__})") from e
        if r.status_code >= 400:
            raise MoteurIndisponible(f"la voix rapide a répondu HTTP {r.status_code}")
        return r.content

    async def transcrire(self, audio: bytes, nom: str, langue: str = "") -> str:
        data = {"model": "whisper-1"}
        if langue:
            data["language"] = langue
        r = await self._appel("POST", "/v1/audio/transcriptions", data=data,
                              files={"file": (nom, audio, "application/octet-stream")})
        try:
            return str((r.json() or {}).get("text", "")).strip()
        except ValueError as e:
            raise MoteurIndisponible("transcription illisible") from e
