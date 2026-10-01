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

ANNUAIRE DES CLÉS PERSONNELLES (#1738, phase 2) — des clés PUBLIQUES :
  GET    /moi                 personne  ma clé publiée, mes adresses confiées
  POST   /moi/cle             personne  publier (ou remplacer) ma clé publique
  DELETE /moi/cle             personne  la retirer — les box liées l'apprennent
  GET    /annuaire            personne  clés de cette box et des box liées
  GET    /annuaire/{fpr}.asc  personne  une clé publique
  GET    /annuaire/export     maillage  l'annuaire signé par la clé de box
  GET    /wkd/{dom}/hu/{h}    public    WKD : adresses VÉRIFIÉES seulement
  GET    /wkd/{dom}/policy    public
"""
from __future__ import annotations

import os
from pathlib import Path

import asyncio
import re

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt, require_lecture, require_personne
from secubox_openpgp.personnes import EMPREINTE, RefusCle
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


# ── annuaire des clés personnelles (#1738, phase 2) ───────────────────────────
RAFRAICHIR_S = 1800
DOMAINE_RE = re.compile(r"^[a-z0-9.-]{3,190}$")
HU_RE = re.compile(r"^[ybndrfg8ejkmcpqxot1uwisza345h769]{32}$")


def _personne(user: dict) -> dict:
    """La personne SBX OS derrière la session, calculée ICI depuis le jeton."""
    from secubox_core import capacites  # noqa: PLC0415
    p = capacites.personne_du_porteur(user or {})
    if not p or not p.get("user_uuid"):
        raise HTTPException(403, "aucune personne SBX OS derrière cette session")
    return p


class Publication(BaseModel):
    cle_publique: str = Field(..., min_length=100, max_length=64 * 1024)


@app.get("/moi")
def moi(user=Depends(require_personne)):
    p = _personne(user)
    a = _box().annuaire_cles()
    e = a.mienne(p["user_uuid"])
    return {"pseudo": p.get("pseudo"), "adresses_confiees": sorted(a.adresses_de(p["user_uuid"])),
            "cle": {k: v for k, v in e.items() if k != "personne"} if e else None}


@app.post("/moi/cle")
def moi_publier(req: Publication, user=Depends(require_personne)):
    p = _personne(user)
    b = _box()
    try:
        e = b.annuaire_cles().publier(p["user_uuid"], p.get("pseudo") or "", req.cle_publique)
    except RefusCle as ex:
        raise HTTPException(422, str(ex))
    b.journal("cle_personnelle_publiee", empreinte=e["empreinte"], verifiees=len(e["verifies"]))
    return {k: v for k, v in e.items() if k != "personne"}


@app.delete("/moi/cle")
def moi_retirer(user=Depends(require_personne)):
    p = _personne(user)
    b = _box()
    fpr = b.annuaire_cles().retirer(p["user_uuid"])
    if not fpr:
        raise HTTPException(404, "aucune clé publiée")
    b.journal("cle_personnelle_retiree", empreinte=fpr)
    return {"retiree": fpr}


@app.get("/annuaire")
def annuaire(user=Depends(require_personne)):
    _personne(user)
    b = _box()
    return {"cles": [{k: v for k, v in e.items() if k != "cle_publique"}
                     for e in b.annuaire_cles().toutes(_nom_box())]}


@app.get("/annuaire/export")
def annuaire_export(request: Request):
    """Pour les box liées seulement : la marque n'est posée que par l'écoute
    :8799 ; la preuve, c'est la signature de la clé de box liée au did."""
    if request.headers.get("X-SecuBox-Maillage", "").strip() != "1":
        raise HTTPException(403, "réservé au maillage")
    try:
        armure = _box().export_annuaire()
    except Refus as e:
        raise HTTPException(503, str(e))
    return PlainTextResponse(armure, media_type="application/pgp-signature")


@app.get("/annuaire/{empreinte}.asc")
def annuaire_cle(empreinte: str, user=Depends(require_personne)):
    _personne(user)
    if not EMPREINTE.match(empreinte or ""):
        raise HTTPException(404, "inconnue")
    e = _box().annuaire_cles().par_empreinte(empreinte, _nom_box())
    if not e:
        raise HTTPException(404, "inconnue")
    return PlainTextResponse(e["cle_publique"], media_type="application/pgp-keys")


@app.get("/wkd/{domaine}/hu/{hu}")
def wkd(domaine: str, hu: str, l: str = None):
    """Web Key Directory (draft-koch-openpgp-webkey-service) : public par
    nature. Seules les adresses que la box a confiées à leur personne."""
    if not DOMAINE_RE.match(domaine or "") or not HU_RE.match(hu or ""):
        raise HTTPException(404)
    cle = _box().annuaire_cles().wkd(domaine, hu, l)
    if cle is None:
        raise HTTPException(404)
    return Response(cle, media_type="application/octet-stream",
                    headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "max-age=3600"})


@app.get("/wkd/{domaine}/policy")
def wkd_policy(domaine: str):
    if not DOMAINE_RE.match(domaine or ""):
        raise HTTPException(404)
    return PlainTextResponse("", headers={"Access-Control-Allow-Origin": "*"})


def _nom_box() -> str:
    try:
        return next((p["boxname"] for p in _box().pairs().values() if p["soi"]), "")
    except Exception:  # noqa: BLE001 — annuaire indisponible : sans nom
        return ""


async def _rafraichir_en_boucle() -> None:
    await asyncio.sleep(60)
    while True:
        try:
            await asyncio.to_thread(_box().rafraichir_annuaires)
        except Exception:  # noqa: BLE001 — un pair absent ne fait pas tomber le démon
            pass
        await asyncio.sleep(RAFRAICHIR_S)


@app.on_event("startup")
async def _demarrage() -> None:
    if os.environ.get("SECUBOX_OPENPGP_SANS_RAFRAICHIR") != "1":
        asyncio.create_task(_rafraichir_en_boucle())
