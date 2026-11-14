# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Gestionnaire de médias (#3583, tâche 12) : dossiers `<etat>/medias/{generes,entree}`, administration seulement.

Aucun nom ne vient du client : les identifiants sont produits ici, le type est lu dans l'en-tête du fichier (octets
magiques), jamais dans le nom ni le Content-Type déclarés. Le journal ne reçoit ni nom ni contenu. Le générateur
d'images est hors de l'étape 1 : le dossier `generes` se liste, se sert et se vide, mais rien n'y écrit encore.
"""
import asyncio
import datetime as dt
import json
import os
import re
import secrets
import shutil
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from api import reglages
from api.journal import journal
from api.modeles import PLANCHER_DISQUE
from secubox_core.auth import require_jwt

QUOTA_MEDIAS = 2 * 1024**3
ENTREE_MAX = 50 * 1024**2
ANALYSE_MAX = 4_000_000          # plafond d'une image analysable (comme le POC)
MIMES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp", "gif": "image/gif",
         "mp4": "video/mp4", "webm": "video/webm", "ogg": "audio/ogg"}
DOSSIERS = {"generes": {"png", "ogg", "webm"}, "entree": {"jpg", "png", "webp", "gif", "mp4", "webm"}}
TYPES = {"png": "image", "jpg": "image", "webp": "image", "gif": "image", "mp4": "video", "webm": "video", "ogg": "voix"}
IDENT = re.compile(r"^\d{8}T\d{12}-[0-9a-f]{8}$")
_verrou = threading.Lock()


def medias_dir() -> Path:
    return reglages.etat_dir() / "medias"


def type_reel(entete, autorises):
    """Extension déduite de l'en-tête du fichier (octets magiques), jamais du nom ni du Content-Type déclarés."""
    e = bytes(entete[:64])
    if e.startswith(b"\xff\xd8\xff"):
        r = "jpg"
    elif e.startswith(b"\x89PNG\r\n\x1a\n"):
        r = "png"
    elif e[:4] == b"RIFF" and e[8:12] == b"WEBP":
        r = "webp"
    elif e[:6] in (b"GIF87a", b"GIF89a"):
        r = "gif"
    elif e[4:8] == b"ftyp":
        r = "mp4"
    elif e.startswith(b"\x1a\x45\xdf\xa3") and b"webm" in e:
        r = "webm"
    elif e[:4] == b"OggS":
        r = "ogg"
    else:
        return None
    return r if r in autorises else None


def _dossier(dossier) -> Path:
    if dossier not in DOSSIERS:
        raise HTTPException(404, "dossier inconnu")
    for d in (medias_dir(), medias_dir() / dossier):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    return medias_dir() / dossier


def _ecrire_atomique(cible: Path, octets: bytes):
    tmp = cible.with_name(".tmp-" + secrets.token_hex(6))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(octets)
        os.replace(tmp, cible)
    finally:
        tmp.unlink(missing_ok=True)


def _nouvel_ident():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f") + "-" + secrets.token_hex(4)


def index(dossier) -> list:
    """Médias d'un dossier : seuls comptent un .json valide ET son fichier (régulier, pas un lien)."""
    d = _dossier(dossier)
    sortie = []
    for j in d.glob("*.json"):
        ident = j.stem
        try:
            if not IDENT.match(ident) or j.is_symlink():
                continue
            meta = json.loads(j.read_text(encoding="utf-8"))
            ext = meta.get("ext")
            if meta.get("id") != ident or ext not in DOSSIERS[dossier]:
                continue
            f = d / f"{ident}.{ext}"
            if f.is_symlink() or not f.is_file():
                continue
            taille = f.stat().st_size
        except (OSError, ValueError, AttributeError):
            continue
        entree = {"id": ident, "type": TYPES[ext], "mime": MIMES[ext], "taille": taille, "date": meta.get("date"),
                  "modele": meta.get("modele"), "ext": ext}
        if dossier == "entree":
            entree["analysable"] = ext in ("jpg", "png", "webp") and taille <= ANALYSE_MAX
        sortie.append(entree)
    return sorted(sortie, key=lambda m: m["id"], reverse=True)


def _chemin(dossier, ident):
    """Chemin d'un média : l'identifiant doit figurer dans l'index, le chemin résolu rester dans le dossier."""
    if not IDENT.match(str(ident)):
        raise HTTPException(404, "média inconnu")
    m = next((x for x in index(dossier) if x["id"] == ident), None)
    if not m:
        raise HTTPException(404, "média inconnu")
    d = (medias_dir() / dossier).resolve()
    f = (d / f"{ident}.{m['ext']}").resolve()
    if f.parent != d or not f.is_file():
        raise HTTPException(404, "média inconnu")
    return m, f


def _utilise(dossier) -> int:
    return sum(m["taille"] for m in index(dossier))


def _etat_dossier(dossier) -> dict:
    try:
        d = json.loads((medias_dir() / dossier / ".etat.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {"retires": 0, "dernier": None}
    except (OSError, ValueError):
        return {"retires": 0, "dernier": None}


def _retirer(dossier, ident, ext):
    d = medias_dir() / dossier
    (d / f"{ident}.json").unlink(missing_ok=True)       # l'index d'abord : plus de média visible sans fichier
    (d / f"{ident}.{ext}").unlink(missing_ok=True)


def _public(m) -> dict:
    return {c: v for c, v in m.items() if c != "ext"}


def _resume(dossier) -> dict:
    etat, liste = _etat_dossier(dossier), index(dossier)
    return {"medias": [_public(m) for m in liste], "utilise": sum(m["taille"] for m in liste), "quota": QUOTA_MEDIAS,
            "retires": etat.get("retires", 0), "dernier_retrait": etat.get("dernier")}


def _nettoyer_temporaires(d: Path):
    for t in d.glob(".tmp-*"):
        try:
            if time.time() - t.stat().st_mtime > 3600:
                t.unlink()
        except OSError:
            pass


routeur = APIRouter(prefix="")


@routeur.get("/medias/{dossier}", dependencies=[Depends(require_jwt)])
async def lister(dossier: str):
    return await asyncio.to_thread(_resume, dossier)


@routeur.get("/medias/{dossier}/{ident}/fichier", dependencies=[Depends(require_jwt)])
async def servir(dossier: str, ident: str, telecharger: int = 0):
    m, f = await asyncio.to_thread(_chemin, dossier, ident)
    return FileResponse(f, media_type=m["mime"], headers={
        "Content-Disposition": ("attachment" if telecharger else "inline") + f'; filename="{ident}.{m["ext"]}"',
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store"})


@routeur.delete("/medias/{dossier}/{ident}", dependencies=[Depends(require_jwt)])
async def supprimer(dossier: str, ident: str):
    m, _f = await asyncio.to_thread(_chemin, dossier, ident)
    with _verrou:
        _retirer(dossier, ident, m["ext"])
    journal("media.suppression", dossier=dossier, type=m["type"], taille=m["taille"], issue="ok")
    return {"ok": True}


@routeur.post("/medias/entree", dependencies=[Depends(require_jwt)])
async def deposer(request: Request):
    """Corps brut = le fichier (pas de multipart). Type lu dans l'en-tête, 50 Mo au plus, quota 2 Go, nom produit ici."""
    d = _dossier("entree")
    try:
        annonce = int(request.headers.get("content-length") or 0)
    except ValueError:
        annonce = 0
    if annonce > ENTREE_MAX:
        journal("media.depot", taille=annonce, issue="trop_gros")
        raise HTTPException(413, "fichier : 50 Mo au plus")
    if not annonce:
        raise HTTPException(411, "taille requise")
    if shutil.disk_usage(d).free - annonce < PLANCHER_DISQUE:
        journal("media.depot", taille=annonce, issue="disque")
        raise HTTPException(507, "place insuffisante : 5 Gio doivent rester libres")
    if _utilise("entree") + annonce > QUOTA_MEDIAS:
        journal("media.depot", taille=annonce, issue="quota")
        raise HTTPException(507, "quota de 2 Go atteint : supprimez des médias")
    _nettoyer_temporaires(d)
    tmp = d / (".tmp-" + secrets.token_hex(6))
    total, ext, tete = 0, None, b""
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as sortie:
            async for bloc in request.stream():
                total += len(bloc)
                if total > ENTREE_MAX:
                    raise HTTPException(413, "fichier : 50 Mo au plus")
                if ext is None:
                    tete += bloc
                    if len(tete) >= 64:
                        ext = type_reel(tete, DOSSIERS["entree"])
                        if ext is None:
                            raise HTTPException(415, "type refusé : JPEG, PNG, WebP, GIF, MP4 ou WebM (en-tête vérifié)")
                await asyncio.to_thread(sortie.write, bloc)
        if ext is None:                                # fichier de moins de 64 octets
            ext = type_reel(tete, DOSSIERS["entree"])
        if ext is None or total == 0:
            raise HTTPException(415, "type refusé : JPEG, PNG, WebP, GIF, MP4 ou WebM (en-tête vérifié)")
        with _verrou:
            if _utilise("entree") + total > QUOTA_MEDIAS:
                raise HTTPException(507, "quota de 2 Go atteint : supprimez des médias")
            ident = _nouvel_ident()
            os.replace(tmp, d / f"{ident}.{ext}")
            meta = {"id": ident, "date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                    "type": TYPES[ext], "ext": ext, "taille": total}
            _ecrire_atomique(d / f"{ident}.json", json.dumps(meta).encode())
        journal("media.depot", type=TYPES[ext], taille=total, issue="ok")
        return {"ok": True, "id": ident}
    except HTTPException as e:
        journal("media.depot", taille=total, issue="refuse", code=e.status_code)
        raise
    except OSError as e:
        journal("media.depot", taille=total, issue="echec")
        raise HTTPException(500, "écriture impossible") from e
    finally:
        tmp.unlink(missing_ok=True)
