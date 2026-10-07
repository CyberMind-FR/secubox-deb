# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: connecteur Freebox — API locale (socket /run/secubox/freebox.sock).

  GET  /status          état de la connexion à la Freebox, droits (lecture gardée : require_lecture)
  GET  /autoriser/etat  état de la demande d'autorisation en cours
  GET  /appareils       appareils du réseau (noms, adresses) vus par la Freebox
  GET  /connexion       état de la connexion Internet, IPv6 délégué
  GET  /pare-feu        pare-feu IPv6 et exceptions
  GET  /redirections    redirections de ports IPv4
  POST /autoriser       demande d'autorisation       (administrateur : require_jwt)
  POST /revoquer        oublier l'autorisation       (administrateur)
  GET  /explorer        lecture brute d'un chemin    (administrateur)
  GET  /health          vivacité (publique)

Le jeton d'application ne sort jamais de la box : aucune route ne le rend.
"""
from __future__ import annotations

import os
import re

from fastapi import Depends, FastAPI, Query
from fastapi.responses import JSONResponse

from secubox_core.auth import require_jwt, require_lecture

from . import client as C
from . import magasin as M
from . import service as S

app = FastAPI(title="SecuBox Freebox", version="0.3.0")

CHEMIN_MAGASIN = os.environ.get("SECUBOX_FREEBOX_MAGASIN", "/var/lib/secubox/freebox/app.json")
HOTE = os.environ.get("SECUBOX_FREEBOX_HOTE", C.HOTE_DEFAUT)


def _fabriquer():
    mag = M.Magasin(CHEMIN_MAGASIN)
    return S.Freebox(C.Client(C.transport_http, mag, hote=HOTE), mag)


_service = _fabriquer()

# Lecture brute (administrateur) : seulement ce qui décrit le réseau, jamais la session, le système ni les redémarrages.
_EXPLORER_OK = re.compile(r"^(lan|connection|fw|network|dhcp|nat|ipv6|wifi)/[a-z0-9_./-]*$")


def _repondre(f):
    """Exécute `f` et traduit les erreurs en codes HTTP et messages clairs (jamais de trace technique)."""
    try:
        return f()
    except C.NonAutorise as e:
        return JSONResponse({"erreur": str(e)}, status_code=409)
    except C.DroitManquant as e:
        return JSONResponse({"erreur": str(e), "droit_manquant": True}, status_code=403)
    except C.Injoignable as e:
        return JSONResponse({"erreur": str(e)}, status_code=503)
    except C.ErreurFreebox as e:
        return JSONResponse({"erreur": str(e)}, status_code=502)
    except ValueError as e:
        return JSONResponse({"erreur": str(e)}, status_code=400)


@app.get("/health")
async def health():
    return {"status": "ok", "module": "freebox"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    return _service.statut()


@app.get("/autoriser/etat", dependencies=[Depends(require_lecture)])
def autoriser_etat():
    return _repondre(_service.etat_autorisation)


@app.get("/appareils", dependencies=[Depends(require_lecture)])
def appareils():
    return _repondre(lambda: {"appareils": _service.appareils()})


@app.get("/connexion", dependencies=[Depends(require_lecture)])
def connexion():
    return _repondre(_service.connexion)


@app.get("/pare-feu", dependencies=[Depends(require_lecture)])
def pare_feu():
    return _repondre(_service.pare_feu)


@app.get("/redirections", dependencies=[Depends(require_lecture)])
def redirections():
    return _repondre(lambda: {"redirections": _service.redirections()})


@app.post("/autoriser", dependencies=[Depends(require_jwt)])
def autoriser():
    return _repondre(_service.autoriser)


@app.post("/pare-feu/ipv6", dependencies=[Depends(require_jwt)])
def regler_pare_feu_ipv6(corps: dict):
    # Écriture : administrateur, valeur voulue ET confirmation explicite dans le corps.
    if corps.get("confirme") is not True or not isinstance(corps.get("actif"), bool):
        return JSONResponse({"erreur": "Confirmation explicite et valeur « actif » (vrai/faux) requises."}, status_code=400)
    return _repondre(lambda: _service.regler_pare_feu_ipv6(corps["actif"]))


@app.get("/upnp", dependencies=[Depends(require_lecture)])
def upnp():
    return _repondre(_service.upnp)


@app.post("/upnp", dependencies=[Depends(require_jwt)])
def regler_upnp(corps: dict):
    if corps.get("confirme") is not True or not isinstance(corps.get("actif"), bool):
        return JSONResponse({"erreur": "Confirmation explicite et valeur « actif » (vrai/faux) requises."}, status_code=400)
    return _repondre(lambda: _service.regler_upnp(corps["actif"]))


@app.post("/revoquer", dependencies=[Depends(require_jwt)])
def revoquer():
    return _repondre(_service.revoquer)


@app.get("/explorer", dependencies=[Depends(require_jwt)])
def explorer(chemin: str = Query(..., max_length=120)):
    if not _EXPLORER_OK.match(chemin) or ".." in chemin or "//" in chemin:
        return JSONResponse({"erreur": "chemin non autorisé"}, status_code=400)
    return _repondre(lambda: {"chemin": chemin, "resultat": _service.explorer(chemin)})
