# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Voix par réplique, reprise idempotente (#4058, Task 10).

Chaque réplique dite devient `voix/<rang>-<sha256(texte+voix)[:12]>.mp3` dans le brouillon. Un fichier présent n'est
jamais refait : une réplique modifiée change d'empreinte et seule sa voix est refaite (l'ancienne est ôtée). Les
répliques `retiree` ne sont jamais dites. Les voix manquantes sont toutes faites en UN passage sous `verrou.voix()`
(Gemma suspendu) ; rien à faire → le GPU n'est pas touché.

Le Voice Studio LOCAL de gk0 (service utilisateur `voicestudio-worker`, décision du 28/11) est joint sur
`http://127.0.0.1:3910` (réglage `voix_url`), contrat OpenAI `POST /v1/audio/speech` (aucun import croisé : processus
séparé). Sur la boucle locale il n'exige pas de clé ; si `~/.config/secubox-ai-jeton/voicestudio` existe (0600), elle
est posée en `Authorization: Bearer`.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from .gpu import VerrouGPU, par_relais

WORKER = os.environ.get("SECUBOX_AI_EMISSIONS_VOIX", "http://127.0.0.1:3910")
CLE_DEFAUT = Path.home() / ".config/secubox-ai-jeton/voicestudio"
VOIX_DEFAUT = {1: "nova", 2: "onyx"}
TEXTE_MAX = 2000


def cle_fichier(chemin: Path = CLE_DEFAUT, facultative: bool = True) -> Callable[[], str]:
    """Lecteur de la clé du worker ; fichier absent et clé facultative → "" (aucun en-tête)."""
    def lire() -> str:
        if facultative and not Path(chemin).exists():
            return ""
        if stat.S_IMODE(os.stat(chemin).st_mode) & 0o077:
            raise PermissionError(f"{chemin} doit être en 0600")
        return Path(chemin).read_text(encoding="ascii").strip()
    return lire


class MoteurVoix:
    """Client minimal du worker : `dire(texte, voix, format_="mp3") -> bytes`. Toute défaillance lève RuntimeError."""

    def __init__(self, url: str = WORKER, cle: Callable[[], str] = cle_fichier(), uds: Optional[str] = None) -> None:
        self.url, self._cle, self.uds = url.rstrip("/"), cle, uds

    async def dire(self, texte: str, voix: str, format_: str = "mp3", delai_s: float = 120) -> bytes:
        charge = {"model": "tts-1", "input": texte, "voice": voix, "response_format": format_}
        transport = httpx.AsyncHTTPTransport(uds=self.uds) if self.uds else None
        cle = self._cle()
        entetes = {"Authorization": f"Bearer {cle}"} if cle else {}
        try:
            async with httpx.AsyncClient(trust_env=False, transport=transport,
                                         timeout=httpx.Timeout(delai_s, connect=10.0)) as c:
                r = await c.post(self.url + "/v1/audio/speech", json=charge, headers=entetes)
        except (httpx.HTTPError, OSError) as e:
            raise RuntimeError(f"worker de voix injoignable ({type(e).__name__})") from e
        if r.status_code >= 400:
            raise RuntimeError(f"le worker de voix a répondu HTTP {r.status_code}")
        if not r.content:
            raise RuntimeError("le worker de voix a rendu un son vide")
        return r.content


def nom_fichier(replique: Dict[str, Any], voix: str) -> str:
    h = hashlib.sha256((replique["texte"] + voix).encode("utf-8")).hexdigest()[:12]
    return f"{int(replique['rang'])}-{h}.mp3"


def _valider(r: Dict[str, Any], voix: Dict[int, str]) -> None:
    rang = r.get("rang")
    if not isinstance(rang, int) or isinstance(rang, bool) or rang < 0:
        raise ValueError(f"rang invalide : {rang!r}")
    if r.get("voix") not in voix:
        raise ValueError(f"voix inconnue pour la réplique {rang}")
    t = r.get("texte")
    if not isinstance(t, str) or not t.strip() or len(t) > TEXTE_MAX:
        raise ValueError(f"texte vide ou trop long pour la réplique {rang}")


def _ecrire(chemin: Path, data: bytes) -> None:
    tmp = chemin.with_name(chemin.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, chemin)


async def dire_tout(brouillon: Path, repliques: List[Dict[str, Any]], voix: Dict[int, str] = VOIX_DEFAUT,
                    delai_s: int = 120, *, moteur: Optional[MoteurVoix] = None,
                    verrou: Optional[VerrouGPU] = None) -> List[Path]:
    """Les fichiers voix des répliques dites, dans l'ordre des rangs ; ne fait que les manquantes."""
    dites = sorted((r for r in repliques if r.get("statut") != "retiree"), key=lambda r: r.get("rang", -1)
                   if isinstance(r.get("rang"), int) else -1)
    for r in dites:
        _valider(r, voix)
    if len({r["rang"] for r in dites}) != len(dites):
        raise ValueError("rangs en double")
    dossier = Path(brouillon) / "voix"
    plan = [(r, dossier / nom_fichier(r, voix[r["voix"]])) for r in dites]
    a_faire = [(r, p) for r, p in plan if not p.is_file()]
    if a_faire:
        dossier.mkdir(parents=True, exist_ok=True, mode=0o700)
        moteur = moteur or MoteurVoix()
        verrou = verrou or par_relais()
        async with verrou.voix():
            for r, p in a_faire:
                _ecrire(p, await moteur.dire(r["texte"], voix[r["voix"]], "mp3", delai_s))
    gardes = {p.name for _, p in plan}
    if dossier.is_dir():
        for p in dossier.glob("*.mp3"):                       # voix périmées (réplique modifiée ou retirée)
            if p.name not in gardes:
                p.unlink(missing_ok=True)
    return [p for _, p in plan]
