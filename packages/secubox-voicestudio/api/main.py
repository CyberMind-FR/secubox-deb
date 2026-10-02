# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: VoiceStudio — API du module (#1917)
CyberMind — https://cybermind.fr

DEUX FACETTES, UNE SEULE API (cf. WEBUI-PANEL-GUIDELINES § 7) :

  administration   require_jwt     /detail /start /stop /restart /installer /config /publier
                                   /cle /cle/renouveler /journal /sauvegarde /voix /essai/*
  usager           require_personne /usager/etat /usager/voix /usager/dire /usager/transcrire

L'API tourne sans privilège (`secubox`). TOUT ce qui touche au LXC, à systemd ou aux fichiers
root passe par `voicestudioctl api` : une seule porte, un seul argv dans sudoers, JSON sur stdin,
actions en liste blanche, audit par le ctl. Elle ne lit JAMAIS la clé du moteur dans un fichier :
le ctl la lui remet en mémoire, et elle n'est jamais renvoyée à un navigateur (sauf à
l'administrateur, UNE fois, au renouvellement).

Le moteur est joint par le mandataire de l'hôte (127.0.0.1:3900) : en mode « à la demande », c'est
lui qui réveille le LXC, et le premier appel attend le démarrage à froid.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt, require_lecture, require_personne

from .moteur import FORMATS, Moteur, MoteurIndisponible

log = logging.getLogger("voicestudio")

app = FastAPI(title="SecuBox VoiceStudio", version="0.2.0")

CTL_ARGV = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet",
            "/usr/sbin/voicestudioctl", "api"]
CONF = Path(os.environ.get("SECUBOX_VS_CONF", "/etc/secubox/voicestudio.toml"))
CONF_DEFAUT = Path(os.environ.get("SECUBOX_VS_CONF_DEFAUT", "/usr/share/secubox/voicestudio/voicestudio.toml"))
MOTEUR_URL = os.environ.get("SECUBOX_VS_URL", "http://127.0.0.1:3900")
TTL_STATUT = 4.0
TTL_CLE = 300.0
SANS_CACHE = {"Cache-Control": "no-store"}


_LIMITES: dict = {"t": 0.0, "v": None}


def _limites() -> dict:
    """Limites des routes d'usager : TOML de la box, sinon celui du paquet, sinon valeurs sûres.
    Relu au plus toutes les 10 s (appelé depuis des routes async : pas de lecture de fichier à chaque appel)."""
    if _LIMITES["v"] is not None and time.monotonic() - _LIMITES["t"] < 10:
        return _LIMITES["v"]
    out = {"texte_max": 2000, "audio_max_mo": 10, "delai_s": 120}
    for f in (CONF_DEFAUT, CONF):
        try:
            with open(f, "rb") as h:
                out.update(tomllib.load(h).get("limites", {}))
        except FileNotFoundError:
            continue
        except (OSError, tomllib.TOMLDecodeError) as e:
            log.warning("limites : %s illisible (%s) — valeurs précédentes gardées", f, type(e).__name__)
    _LIMITES.update(t=time.monotonic(), v=out)
    return out


# ── porte du ctl ─────────────────────────────────────────────────────────────
def _executer(requete: dict, delai: int) -> dict:
    """Appelle voicestudioctl api. Ne lève que HTTPException : l'état doit toujours rendre."""
    try:
        p = subprocess.run(CTL_ARGV, input=json.dumps(requete), capture_output=True, text=True,
                           timeout=delai, check=False)
    except subprocess.TimeoutExpired as e:
        raise HTTPException(504, "voicestudioctl : délai dépassé") from e
    except OSError as e:
        raise HTTPException(503, "voicestudioctl indisponible") from e
    try:
        rep = json.loads(p.stdout or "{}")
    except ValueError as e:
        log.warning("voicestudioctl : sortie illisible (rc=%s) %s", p.returncode, (p.stderr or "")[:200])
        raise HTTPException(502, "réponse du ctl illisible") from e
    if p.returncode != 0 or rep.get("ok") is False:
        raise HTTPException(400, str(rep.get("erreur") or rep.get("detail") or "action refusée")[:300])
    return rep


def _ctl(action: str, par: str = "", delai: int = 60, **params) -> dict:
    return _executer({"action": action, "par": par, **params}, delai)


def _par(payload: dict) -> str:
    return str(payload.get("sub", ""))[:64]


# ── statut (cache serveur court) ─────────────────────────────────────────────
_CACHE_STATUT: dict = {"t": 0.0, "v": None, "err": None}
_VERROU_STATUT = threading.Lock()


def _statut(force: bool = False) -> dict:
    """Statut du ctl, en cache quelques secondes — ÉCHECS COMPRIS : un ctl lent ou absent ne doit pas
    être ré-interrogé (sudo + systemd-run) à chaque requête d'un client qui insiste."""
    with _VERROU_STATUT:
        frais = time.monotonic() - _CACHE_STATUT["t"] < TTL_STATUT
        if not force and frais and (_CACHE_STATUT["v"] is not None or _CACHE_STATUT["err"] is not None):
            if _CACHE_STATUT["err"] is not None:
                raise _CACHE_STATUT["err"]
            return _CACHE_STATUT["v"]
        try:
            v = _ctl("status", delai=30)
        except HTTPException as e:
            _CACHE_STATUT.update(t=time.monotonic(), v=None, err=e)
            raise
        _CACHE_STATUT.update(t=time.monotonic(), v=v, err=None)
        return v


# ── opération longue (démarrage à froid, installation) hors de la requête ────
_OP: dict = {"action": None, "etat": "repos", "debut": None, "fin": None, "ok": None, "detail": ""}
_VERROU_OP = threading.Lock()
_DELAIS_OP = {"start": 300, "restart": 300, "stop": 90, "installer": 3600}


def _travail(action: str, par: str) -> None:
    ok, detail = False, ""
    try:
        rep = _ctl(action, par=par, delai=_DELAIS_OP[action])
        ok, detail = True, str(rep.get("detail", ""))[:300]
    except HTTPException as e:
        detail = str(e.detail)
    except Exception as e:  # noqa: BLE001 — un thread ne doit jamais mourir sans le dire
        log.exception("opération %s en échec", action)
        detail = type(e).__name__
    with _VERROU_OP:
        _OP.update(etat="termine", fin=datetime.now(timezone.utc).isoformat(), ok=ok, detail=detail)
    if ok:
        try:
            _statut(force=True)
        except HTTPException:
            pass            # le prochain /status relira ; l'opération, elle, a réussi


def _lancer(action: str, par: str) -> dict:
    with _VERROU_OP:
        if _OP["etat"] == "en-cours":
            raise HTTPException(409, f"opération « {_OP['action']} » déjà en cours")
        _OP.update(action=action, etat="en-cours", debut=datetime.now(timezone.utc).isoformat(),
                   fin=None, ok=None, detail="")
        etat = dict(_OP)
    threading.Thread(target=_travail, args=(action, par), daemon=True, name=f"vs-{action}").start()
    return etat


# ── clé du moteur, en mémoire seulement ──────────────────────────────────────
_CLE: dict = {"v": "", "t": 0.0}


async def _cle() -> str:
    if _CLE["v"] and time.monotonic() - _CLE["t"] < TTL_CLE:
        return _CLE["v"]
    rep = await asyncio.to_thread(_ctl, "cle-interne", "", 20)
    _CLE.update(v=str(rep.get("cle", "")), t=time.monotonic())
    return _CLE["v"]


def _oublier_cle() -> None:
    _CLE.update(v="", t=0.0)


def _moteur() -> Moteur:
    return Moteur(MOTEUR_URL, _cle, int(_limites()["delai_s"]))


# ── schémas ──────────────────────────────────────────────────────────────────
IPV4 = r"^(?:\d{1,3}\.){3}\d{1,3}$"


class ConfigIn(BaseModel):
    asr: Optional[str] = Field(None, max_length=64)
    memoire: Optional[str] = Field(None, pattern=r"^[1-9][0-9]{0,4}[GM]$")
    cpu_poids: Optional[int] = Field(None, ge=1, le=10000)
    mode: Optional[Literal["permanent", "demande"]] = None
    inactivite_s: Optional[int] = Field(None, ge=60, le=86400)


class PublierIn(BaseModel):
    adresses: list[str] = Field(default_factory=list, max_length=8)


class DireIn(BaseModel):
    texte: str = Field(..., min_length=1, max_length=20000)
    voix: str = Field("", pattern=r"^(?:[\w][\w .:@+-]{0,63})?$")
    format: Literal["mp3", "wav", "opus"] = "mp3"


# ── santé, statut ────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "module": "voicestudio"}


def _operation() -> dict:
    with _VERROU_OP:
        return dict(_OP)


@app.get("/status", dependencies=[Depends(require_lecture)])
def status() -> dict:
    """État MINIMAL, lisible en mode tableau de bord depuis le LAN : ni adresses, ni IP du conteneur,
    ni commit (la topologie est du ressort de l'administrateur : /detail)."""
    op = _operation()
    try:
        s = _statut()
    except HTTPException as e:
        return {"module": "voicestudio", "version": app.version, "installed": False, "running": False,
                "error": str(e.detail), "operation": {"etat": op["etat"], "action": op["action"]}}
    return {"module": "voicestudio", "version": app.version, "installed": s.get("installe", False),
            "running": bool(s.get("moteur")), "asleep": s.get("lxc") == "STOPPED",
            "operation": {"etat": op["etat"], "action": op["action"]}}


@app.get("/detail", dependencies=[Depends(require_jwt)])
def detail() -> dict:
    """État COMPLET pour le panneau d'administration. Aucun secret : l'aperçu de la clé est /cle."""
    op = _operation()
    try:
        s = _statut()
    except HTTPException as e:
        return {"module": "voicestudio", "version": app.version, "installed": False, "running": False,
                "error": str(e.detail), "operation": op}
    return {**s, "module": "voicestudio", "version": app.version, "installed": s.get("installe", False),
            "running": bool(s.get("moteur")), "asleep": s.get("lxc") == "STOPPED",
            "operation": op, "limites": _limites()}


# ── administration (require_jwt) ─────────────────────────────────────────────
@app.post("/start", status_code=202)
def demarrer(qui: dict = Depends(require_jwt)) -> dict:
    return {"operation": _lancer("start", _par(qui))}


@app.post("/stop", status_code=202)
def arreter(qui: dict = Depends(require_jwt)) -> dict:
    return {"operation": _lancer("stop", _par(qui))}


@app.post("/restart", status_code=202)
def redemarrer(qui: dict = Depends(require_jwt)) -> dict:
    return {"operation": _lancer("restart", _par(qui))}


@app.post("/installer", status_code=202)
def installer(qui: dict = Depends(require_jwt)) -> dict:
    """Provisionnement (10 à 25 min : torch, dépendances). Hors requête, suivi par /status."""
    return {"operation": _lancer("installer", _par(qui))}


@app.post("/config")
def configurer(corps: ConfigIn, qui: dict = Depends(require_jwt)) -> dict:
    """Une valeur à la fois côté ctl : chacune est revalidée par liste blanche ou motif entier."""
    voulu = {k: v for k, v in corps.model_dump().items() if v is not None}
    if not voulu:
        raise HTTPException(422, "aucune valeur à appliquer")
    appliques = {}
    for cle, valeur in voulu.items():
        _ctl("config", par=_par(qui), delai=90, cle=cle, valeur=str(valeur))
        appliques[cle] = valeur
    _statut(force=True)
    return {"ok": True, "appliques": appliques}


@app.post("/publier")
def publier(corps: PublierIn, qui: dict = Depends(require_jwt)) -> dict:
    for a in corps.adresses:
        if not re.fullmatch(IPV4, a):
            raise HTTPException(422, f"adresse invalide : {a[:40]}")
    _ctl("publier", par=_par(qui), delai=60, adresses=corps.adresses)
    _statut(force=True)
    return {"ok": True, "publier": corps.adresses}


@app.get("/cle", dependencies=[Depends(require_jwt)])
def apercu_cle() -> JSONResponse:
    """Aperçu (4 premiers et 4 derniers caractères) : jamais la clé entière."""
    r = _ctl("cle-apercu", delai=20)
    return JSONResponse({"presente": r.get("presente", False), "apercu": r.get("apercu", "")}, headers=SANS_CACHE)


@app.post("/cle/renouveler")
def renouveler_cle(qui: dict = Depends(require_jwt)) -> JSONResponse:
    """Nouvelle clé, rendue UNE fois. Les autres box qui consomment le moteur (voice.toml [distant]
    cle) doivent la recevoir : l'ancienne est morte dès cet appel."""
    r = _ctl("cle-renouveler", par=_par(qui), delai=90)
    _oublier_cle()
    return JSONResponse({"ok": True, "cle": r.get("cle", "")}, headers=SANS_CACHE)


@app.get("/journal", dependencies=[Depends(require_jwt)])
def journal(n: int = Query(100, ge=1, le=500)) -> dict:
    return {"lignes": _ctl("logs", delai=40, n=n).get("lignes", [])}


@app.post("/sauvegarde")
def sauvegarde(qui: dict = Depends(require_jwt)) -> dict:
    r = _ctl("sauvegarde", par=_par(qui), delai=600)
    return {"ok": True, "fichier": Path(str(r.get("detail", ""))).name}


# ── voix : synthèse et reconnaissance (une implémentation, deux gardes) ──────
_DEBIT: dict = {}
# Deux verrous : un usager qui occupe le moteur (jusqu'à 120 s) ne prive pas l'administrateur de son essai.
_UN_A_LA_FOIS = asyncio.Semaphore(1)
_UN_A_LA_FOIS_ADMIN = asyncio.Semaphore(1)


def _debit(qui: dict, geste: str, maxi: int) -> None:
    cle, maint = (str(qui.get("sub")), geste), time.time()
    if len(_DEBIT) > 500:                       # purge : une clé par personne et par geste ne grossit pas sans fin
        for k in [k for k, v in _DEBIT.items() if not v or maint - v[-1] > 60]:
            del _DEBIT[k]
    t = [x for x in _DEBIT.get(cle, []) if maint - x < 60]
    if len(t) >= maxi:
        _DEBIT[cle] = t
        raise HTTPException(429, "Trop de demandes vocales, réessayez dans une minute.")
    _DEBIT[cle] = t + [maint]


async def _tour(sem: asyncio.Semaphore) -> None:
    try:
        await asyncio.wait_for(sem.acquire(), timeout=20)
    except asyncio.TimeoutError as e:
        raise HTTPException(429, "Le moteur est occupé, réessayez.") from e


def _indisponible(e: MoteurIndisponible) -> HTTPException:
    if "clé" in str(e):
        _oublier_cle()
    # 503 et non 500 : ce n'est pas un bogue, c'est un moteur absent.
    return HTTPException(503, f"VoiceStudio indisponible : {e}")


async def _liste_voix() -> dict:
    try:
        return {"voix": await _moteur().voix()}
    except MoteurIndisponible as e:
        raise _indisponible(e) from e


async def _dire(corps: DireIn, qui: dict, sem: asyncio.Semaphore) -> Response:
    _debit(qui, "dire", 20)
    texte = corps.texte.strip()
    maxi = int(_limites()["texte_max"])
    if not texte:
        raise HTTPException(400, "Texte vide.")
    if len(texte) > maxi:
        raise HTTPException(413, f"Texte trop long ({len(texte)} caractères, maximum {maxi}). "
                                 "Découpez-le : une voix se pilote par phrases.")
    await _tour(sem)
    try:
        audio = await _moteur().dire(texte, corps.voix, corps.format)
    except MoteurIndisponible as e:
        raise _indisponible(e) from e
    finally:
        sem.release()
    return Response(content=audio, media_type=FORMATS[corps.format], headers=SANS_CACHE)


async def _transcrire(fichier: UploadFile, langue: str, qui: dict, sem: asyncio.Semaphore) -> JSONResponse:
    _debit(qui, "transcrire", 12)
    if langue and not re.fullmatch(r"[a-z]{2,3}(-[A-Za-z]{2,4})?", langue):
        raise HTTPException(422, "langue : code ISO (fr, en, pt-BR…) ou vide pour détection")
    maxi = int(_limites()["audio_max_mo"]) * 1024 * 1024
    audio = await fichier.read(maxi + 1)
    if len(audio) > maxi:
        raise HTTPException(413, f"Audio trop volumineux (maximum {maxi // (1024 * 1024)} Mo).")
    if not audio:
        raise HTTPException(400, "Audio vide.")
    await _tour(sem)
    try:
        texte = await _moteur().transcrire(audio, (fichier.filename or "audio")[:80], langue)
    except MoteurIndisponible as e:
        raise _indisponible(e) from e
    finally:
        sem.release()
    return JSONResponse({"texte": texte, "vide": not texte, "langue": langue or "auto"}, headers=SANS_CACHE)


# Administrateur : essai du moteur depuis le panneau d'administration.
@app.get("/voix", dependencies=[Depends(require_jwt)])
async def voix_admin() -> dict:
    return await _liste_voix()


@app.post("/essai/dire")
async def essai_dire(corps: DireIn, qui: dict = Depends(require_jwt)) -> Response:
    return await _dire(corps, qui, _UN_A_LA_FOIS_ADMIN)


@app.post("/essai/transcrire")
async def essai_transcrire(fichier: UploadFile = File(...), langue: str = Form(""),
                           qui: dict = Depends(require_jwt)) -> JSONResponse:
    return await _transcrire(fichier, langue, qui, _UN_A_LA_FOIS_ADMIN)


# Usager : dire et écouter demandent une PERSONNE connectée (require_personne : jamais un visiteur
# ni un appareil invité), avec un débit borné par personne et un seul calcul à la fois.
@app.get("/usager/etat", dependencies=[Depends(require_personne)])
def usager_etat() -> dict:
    """Ce que l'interface d'usager doit savoir pour être honnête : le moteur répond-il, endormi ?"""
    try:
        s = _statut()
    except HTTPException:
        return {"disponible": False, "motif": "module indisponible", "limites": _limites()}
    dort = s.get("lxc") == "STOPPED"
    return {"disponible": bool(s.get("moteur")) or (dort and s.get("mode") == "demande"),
            "reveil_necessaire": dort, "demarrage": bool(s.get("demarrage")), "mode": s.get("mode"),
            "limites": {k: v for k, v in _limites().items() if k in ("texte_max", "audio_max_mo")}}


@app.get("/usager/voix")
async def usager_voix(qui: dict = Depends(require_personne)) -> dict:
    _debit(qui, "voix", 30)
    return await _liste_voix()


@app.post("/usager/dire")
async def usager_dire(corps: DireIn, qui: dict = Depends(require_personne)) -> Response:
    return await _dire(corps, qui, _UN_A_LA_FOIS)


@app.post("/usager/transcrire")
async def usager_transcrire(fichier: UploadFile = File(...), langue: str = Form(""),
                            qui: dict = Depends(require_personne)) -> JSONResponse:
    return await _transcrire(fichier, langue, qui, _UN_A_LA_FOIS)
