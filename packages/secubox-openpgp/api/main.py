# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — le démon (#1736)
CyberMind — https://cybermind.fr

/run/secubox/openpgp.sock, utilisateur secubox-openpgp. La clé privée de la
box vit dans son GNUPGHOME et n'en sort jamais : aucune route ne la rend,
aucune ne signe ni ne déchiffre des octets fournis par l'appelant (#1417, S8).

  GET  /health                 sonde
  GET  /status        lecture  did, clé de la box, liaison publiée, pairs
  GET  /pairs         lecture  box liées dans l'annuaire (empreinte, adresse)
  GET  /cle           lecture  NOTRE clé publique (armure)
  POST /envoyer       admin    enveloppe signée + chiffrée vers un pair lié
  GET  /boite         admin    messages reçus (métadonnées)
  GET  /boite/{id}    admin    un message, déchiffré — tracé
  POST /boite/depot   maillage dépôt d'un pair (écoute :8799 seulement) ;
                               TOUT est vérifié, la réponse ne dit pas pourquoi
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt, require_lecture
from secubox_openpgp.gpg import ErreurGpg, Trousseau
from secubox_openpgp.service import Box, Refus, did_local

RACINE = Path(os.environ.get("SECUBOX_OPENPGP_RACINE", "/var/lib/secubox/openpgp"))
GNUPGHOME = os.environ.get("GNUPGHOME", str(RACINE / "node"))
MAX_DEPOT = 256 * 1024

app = FastAPI(title="SecuBox OpenPGP", version="0.1.0")


def _box() -> Box:
    return Box(trousseau=Trousseau(GNUPGHOME), did=did_local(), racine=RACINE)


@app.get("/health")
def health():
    return {"ok": True, "module": "openpgp"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    b = _box()
    cle = b.ma_cle()
    try:
        pairs = b.pairs()
        annuaire = True
    except Exception:  # noqa: BLE001 — annuaire indisponible : on le dit
        pairs, annuaire = {}, False
    moi = pairs.get(b.did)
    return {"did": b.did,
            "cle": {k: cle[k] for k in ("empreinte", "creee", "expire")} if cle else None,
            "liee": bool(cle and moi and moi["empreinte"] == cle["empreinte"]),
            "annuaire": annuaire,
            "pairs": sum(1 for p in pairs.values() if not p["soi"])}


@app.get("/pairs", dependencies=[Depends(require_lecture)])
def pairs():
    try:
        ps = _box().pairs()
    except Refus as e:
        raise HTTPException(503, str(e))
    return {"pairs": [{k: p[k] for k in ("did", "boxname", "mesh_ip", "empreinte", "expire", "soi")}
                      for p in ps.values()]}


@app.get("/cle", dependencies=[Depends(require_lecture)])
def cle():
    b = _box()
    c = b.ma_cle()
    if not c:
        raise HTTPException(404, "pas encore de clé OpenPGP (sbx-openpgp init)")
    return PlainTextResponse(b.trousseau.exporter_public(c["empreinte"]),
                             media_type="application/pgp-keys")


class Envoi(BaseModel):
    pair: str = Field(..., min_length=3, max_length=64, description="did ou nom de box")
    objet: str = Field(..., max_length=200)
    contenu: str = Field(..., max_length=128 * 1024)


@app.post("/envoyer")
def envoyer(req: Envoi, user=Depends(require_jwt)):
    b = _box()
    try:
        r = b.envoyer(req.pair, req.objet, req.contenu)
    except (Refus, ErreurGpg) as e:
        raise HTTPException(422, str(e))
    b.journal("envoi_par", qui=str(user.get("sub", "")), a=r["a"])
    return r


@app.get("/boite")
def boite(user=Depends(require_jwt)):
    return {"messages": _box().lister()}


@app.get("/boite/{ident}")
def lire(ident: str, user=Depends(require_jwt)):
    b = _box()
    try:
        m = b.lire(ident)
    except (Refus, ErreurGpg) as e:
        raise HTTPException(404, str(e))
    b.journal("lecture_par", qui=str(user.get("sub", "")), id=ident)
    return m


@app.post("/boite/depot")
async def depot(request: Request):
    """Dépôt d'un pair du maillage. La marque n'est posée que par l'écoute
    :8799 (10.10.0.0/24) et vidée partout ailleurs par secubox-proxy.conf ;
    elle n'est qu'une borne : la preuve est cryptographique."""
    if request.headers.get("X-SecuBox-Maillage", "").strip() != "1":
        raise HTTPException(403, "dépôt réservé au maillage")
    corps = await request.body()
    if not corps or len(corps) > MAX_DEPOT:
        return JSONResponse({"ok": False, "detail": "message refusé"}, status_code=422)
    try:
        texte = corps.decode("ascii")
    except UnicodeDecodeError:
        return JSONResponse({"ok": False, "detail": "message refusé"}, status_code=422)
    import asyncio  # noqa: PLC0415
    try:
        r = await asyncio.to_thread(_box().deposer, texte)
    except Refus:
        return JSONResponse({"ok": False, "detail": "message refusé"}, status_code=422)
    return JSONResponse(r, status_code=201)
