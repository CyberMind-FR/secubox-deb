# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Voice — les oreilles et la bouche de SBXOS (#1287).
CyberMind — https://cybermind.fr

CE MODULE NE COMPREND RIEN. Il transcrit et il prononce ; c'est tout. L'intention,
la politique de rôle et l'action reviennent à ZIA, qui sait déjà les faire : la
couche d'action (RFC) traduit déjà « mets la radio en pause » en `media.pause` sur
le service `radio`. Lui adjoindre un second cerveau vocal serait dédoubler le seul
endroit du système qui a le droit de décider.

D'OÙ LA BOUCLE :

    micro (navigateur) → POST /asr            ← ici, transcription
                       → POST /api/v1/zia/v1/chat   ← ZIA : intention + action
                       → postMessage sbx            ← le Hall agit sur la cardlet
                       → POST /tts            ← ici, la réponse prend une voix

LECTURE GARDÉE. Un micro est l'entrée la plus intime d'une box. Les routes qui
produisent ou consomment de l'audio exigent donc un jeton — jamais le régime
« ouvert au LAN » qu'on accorde à des compteurs de menaces.
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

import asyncio
import time

from secubox_core.auth import router as auth_router, require_jwt, require_personne
from secubox_core.logger import get_logger

from .moteur import MoteurIndisponible, construire
from . import commandes
from .profils import Profils

log = get_logger("voice")

CONFIG_FILE = Path("/etc/secubox/voice.toml")

DEFAULT_CONFIG: dict = {
    # « local » (défaut, souverain) ou « distant ». Voir moteur.construire().
    "moteur": "local",
    "voix_defaut": "lexie-fr",
    # Garde-fous : une synthèse n'est pas un moyen de faire lire un livre entier
    # à la box, et un envoi audio n'est pas un moyen d'y téléverser un film.
    "texte_max": 2000,
    "audio_max_mo": 10,
    "local": {},
    "distant": {},
    "profils": {},
}


def _cfg() -> dict:
    """Lit la configuration, en gardant les défauts pour tout ce qui manque.

    Un fichier absent ou cassé ne doit pas empêcher le service de démarrer : il
    démarrera « moteur local incomplet », ce qui est un état lisible, là où un
    refus de démarrer ne dirait rien à personne.
    """
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(tomllib.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except FileNotFoundError:
        log.info("voice.toml absent — défauts appliqués (moteur local)")
    except (OSError, tomllib.TOMLDecodeError) as e:
        log.warning("voice.toml illisible (%s) — défauts appliqués", e)
    return cfg


app = FastAPI(title="SecuBox Voice", docs_url=None, redoc_url=None)
router = APIRouter()

_config = _cfg()
_moteur = construire(_config)
_profils = Profils(_config)


class DireIn(BaseModel):
    texte: str = Field(min_length=1)
    # Le profil, PAS la voix : l'appelant dit d'où il parle (« billets »), pas
    # quel fichier de modèle employer. C'est ce qui permet de changer la voix
    # des Billets sans toucher aux Billets.
    profil: Optional[str] = None
    format: str = "wav"


@router.get("/health")
async def health() -> dict:
    return {"module": "voice", "ok": True}


@router.get("/moteur", dependencies=[Depends(require_jwt)])
async def etat_moteur() -> JSONResponse:
    """L'état RÉEL du moteur, pour que la fenêtre de Lexie puisse être honnête.

    Sans cette route, l'interface ne saurait dire « la reconnaissance est
    indisponible » : elle ne pourrait qu'échouer au premier appui sur le micro,
    ce qui fait porter la panne à l'utilisateur au lieu de la lui annoncer.
    """
    e = await _moteur.etat()
    return JSONResponse({
        "genre": e.genre, "joignable": e.joignable, "detail": e.detail,
        "tts": e.tts, "asr": e.asr,
        "voix_defaut": _profils.defaut,
    })


@router.get("/profils", dependencies=[Depends(require_jwt)])
async def liste_profils() -> JSONResponse:
    return JSONResponse({"defaut": _profils.defaut, "profils": _profils.liste()})


# LA VOIX EST OUVERTE AUX PERSONNES (#1615, décision de Gandalf) : dire et
# écouter demandent une personne connectée (require_personne : jamais un
# visiteur ni un appareil invité), avec un débit borné par personne. Le moteur
# charge son modèle à chaque appel et le service n'a qu'un ouvrier : un seul
# calcul à la fois, les autres attendent un peu puis reçoivent 429.
# /moteur et /profils restent réservés à l'administration.
_DEBIT: dict = {}
_UN_A_LA_FOIS = asyncio.Semaphore(1)


def _debit(qui: dict, geste: str, maxi: int) -> Optional[JSONResponse]:
    cle, maint = (str(qui.get("sub")), geste), time.time()
    t = [x for x in _DEBIT.get(cle, []) if maint - x < 60]
    if len(t) >= maxi:
        _DEBIT[cle] = t
        return JSONResponse({"detail": "Trop de demandes vocales, réessayez dans une minute."}, status_code=429)
    _DEBIT[cle] = t + [maint]
    return None


async def _tour():
    try:
        await asyncio.wait_for(_UN_A_LA_FOIS.acquire(), timeout=20)
        return True
    except asyncio.TimeoutError:
        return False


@router.post("/tts")
async def tts(body: DireIn, qui: dict = Depends(require_personne)) -> Response:
    if (r := _debit(qui, "tts", 20)):
        return r
    texte = body.texte.strip()
    if not texte:
        return JSONResponse({"detail": "Texte vide."}, status_code=400)
    maxi = int(_config.get("texte_max", 2000))
    if len(texte) > maxi:
        return JSONResponse(
            {"detail": f"Texte trop long ({len(texte)} caractères, maximum {maxi}). "
                       f"Découpez-le : une voix se pilote par phrases."},
            status_code=413)

    voix, avertissement = _profils.resoud(body.profil)
    if not await _tour():
        return JSONResponse({"detail": "La voix est occupée, réessayez."}, status_code=429)
    try:
        audio = await _moteur.dire(texte, voix, body.format)
    except MoteurIndisponible as e:
        # 503 et non 500 : ce n'est pas un bogue, c'est un moteur absent — et la
        # distinction compte pour qui lit les journaux.
        return JSONResponse({"detail": str(e)}, status_code=503)
    finally:
        _UN_A_LA_FOIS.release()

    entetes = {"X-Voix": voix}
    if avertissement:
        # L'avertissement voyage dans l'en-tête : le corps est de l'audio, on ne
        # va pas y glisser du texte, mais il ne doit pas disparaître pour autant.
        entetes["X-Avertissement"] = avertissement
        log.info("profil vocal inconnu : %s", avertissement)
    mime = {"wav": "audio/wav", "mp3": "audio/mpeg", "opus": "audio/ogg"}.get(
        body.format, "application/octet-stream")
    return Response(content=audio, media_type=mime, headers=entetes)


@router.post("/asr")
async def asr(fichier: UploadFile = File(...), langue: str = Form("fr"),
              qui: dict = Depends(require_personne)) -> JSONResponse:
    if (r := _debit(qui, "asr", 12)):
        return r
    maxi = int(_config.get("audio_max_mo", 10)) * 1024 * 1024
    audio = await fichier.read(maxi + 1)
    if len(audio) > maxi:
        return JSONResponse(
            {"detail": f"Audio trop volumineux (maximum {maxi // (1024*1024)} Mo). "
                       f"Une commande vocale dure quelques secondes."},
            status_code=413)
    if not audio:
        return JSONResponse({"detail": "Audio vide."}, status_code=400)

    # COMMANDE COURANTE D'ABORD (#1656) : grammaire fermée sur la box, ~0,7 s.
    cmd = await asyncio.to_thread(commandes.reconnait, audio)
    if cmd:
        return JSONResponse({"texte": cmd, "vide": False, "langue": langue, "commande": True})

    if not await _tour():
        return JSONResponse({"detail": "La voix est occupée, réessayez."}, status_code=429)
    try:
        texte = await _moteur.transcrire(audio, fichier.filename or "audio.wav")
    except MoteurIndisponible as e:
        return JSONResponse({"detail": str(e)}, status_code=503)
    finally:
        _UN_A_LA_FOIS.release()

    # Une transcription vide est un RÉSULTAT, pas une erreur : l'utilisateur a
    # peut-être simplement relâché le bouton sans rien dire. On le dit tel quel.
    return JSONResponse({"texte": texte, "vide": not texte, "langue": langue})


app.include_router(auth_router)
app.include_router(router)
