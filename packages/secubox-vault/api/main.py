# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-vault 2.0 — API du Coffre (#1367 P1).

DEUX APPLICATIONS, DEUX SOCKETS, UN SEUL COFFRE.

- `public` (/run/secubox/vault.sock) : relayée par l'agrégateur aux seuls
  administrateurs réels. Ouvrir, sceller, état, NOMS des secrets, poser,
  retirer, journal. Elle ne rend JAMAIS la valeur d'un secret : pas d'oracle
  derrière une session web. Elle n'ouvre que depuis le LAN, quand la politique
  n'y exige pas de second facteur ; l'ouverture DISTANTE (TOTP frais, alerte
  courriel) est la phase P4 — d'ici là, `coffrectl ouvrir` en SSH. Cinq échecs
  par heure et par identité, puis 429.
- `racine` (/run/secubox-coffre/racine.sock, répertoire 0700) : celle de
  `coffrectl`, pour root. Initialisation, lecture d'une valeur, serrures,
  codes de secours. Le système de fichiers est la garde.

Le Coffre ne vit QUE dans ce processus : jamais monté dans l'agrégateur, dont
tous les modules partagent la mémoire.
"""
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from secubox_core import second_facteur
from secubox_core.auth import require_jwt

from coffre.coffre import Coffre, Interdit, NonInitialise, Scelle
from coffre.crypto import Refus
from coffre.journal import Journal

VERSION = "2.0.0"
BASE = Path(os.environ.get("SECUBOX_COFFRE_DIR", "/var/lib/secubox/coffre"))
JOURNAL = Path(os.environ.get("SECUBOX_COFFRE_JOURNAL", "/var/log/secubox/coffre.journal"))
DELAI_S = int(os.environ.get("SECUBOX_COFFRE_DELAI_S", "900"))

COFFRE = Coffre(BASE, Journal(JOURNAL), delai_s=DELAI_S)

ESSAIS_MAX = 5
FENETRE_S = 3600
_echecs: dict = defaultdict(deque)


class Ouverture(BaseModel):
    secret: str = Field(min_length=1, max_length=1024)
    genre: str = "phrase"


class Pose(BaseModel):
    compartiment: str = Field(max_length=40)
    nom: str = Field(max_length=64)
    valeur: str = Field(min_length=1, max_length=65536)


class Phrase(BaseModel):
    phrase: str = Field(min_length=1, max_length=1024)
    libelle: str = Field(default="", max_length=80)


class Compartiment(BaseModel):
    id: str = Field(max_length=40)
    libelle: str = Field(default="", max_length=80)


def _traduit(e: Exception) -> HTTPException:
    if isinstance(e, Scelle):
        return HTTPException(423, "Coffre scellé")
    if isinstance(e, NonInitialise):
        return HTTPException(409, "Coffre non initialisé")
    if isinstance(e, Interdit):
        return HTTPException(400, str(e))
    if isinstance(e, KeyError):
        return HTTPException(404, "secret inconnu")
    if isinstance(e, Refus):
        COFFRE.journal.ajouter("integrite", detail="déchiffrement refusé")
        return HTTPException(500, "intégrité : secret illisible")
    raise e


def _appel(fn, *a, **k):
    try:
        return fn(*a, **k)
    except (Scelle, NonInitialise, Interdit, KeyError, Refus) as e:
        raise _traduit(e) from None


def _limite(qui: str) -> None:
    q = _echecs[qui]
    while q and time.monotonic() - q[0] > FENETRE_S:
        q.popleft()
    if len(q) >= ESSAIS_MAX:
        raise HTTPException(429, "trop d'essais — réessayer plus tard")


def _routes_communes(app: FastAPI, garde: list) -> None:
    @app.get("/health")
    def health():
        return {"status": "ok", "module": "vault", "version": VERSION}

    @app.get("/etat", dependencies=garde)
    def etat():
        return COFFRE.etat()

    @app.post("/sceller", dependencies=garde)
    def sceller():
        COFFRE.sceller("commande")
        return COFFRE.etat()

    @app.get("/secrets", dependencies=garde)
    def secrets(compartiment: Optional[str] = None):
        return {"secrets": _appel(COFFRE.lister, compartiment)}

    @app.post("/secrets", dependencies=garde)
    def poser(p: Pose):
        return {"version": _appel(COFFRE.poser, p.compartiment, p.nom, p.valeur.encode())}

    @app.delete("/secrets/{compartiment}/{nom}", dependencies=garde)
    def retirer(compartiment: str, nom: str):
        _appel(COFFRE.retirer, compartiment, nom)
        return {"retire": True}

    @app.get("/journal", dependencies=garde)
    def journal(n: int = 50):
        integre, fautive, lignes = COFFRE.journal.verifier()
        return {"integre": integre, "ligne_fautive": fautive, "lignes": lignes,
                "entrees": COFFRE.journal.derniers(max(1, min(n, 500)))}


# ── public : administrateurs réels, via l'agrégateur ──────────────────────────
public = FastAPI(title="SecuBox Coffre", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
_routes_communes(public, [Depends(require_jwt)])


@public.post("/ouvrir")
def ouvrir_public(o: Ouverture, request: Request, user=Depends(require_jwt)):
    qui = str((user or {}).get("sub") or "?")
    _limite(qui)
    if second_facteur.otp_exige(request):
        # Hors LAN, ou LAN sous politique « second facteur obligatoire » : pas
        # en P1. On le dit, on le journalise, on ne compte pas d'échec.
        COFFRE.journal.ajouter("ouverture_refusee", genre=o.genre, qui=qui, motif="second_facteur")
        raise HTTPException(403, "ouverture avec second facteur : pas encore (phase P4) — coffrectl ouvrir en SSH")
    ok = _appel(COFFRE.ouvrir, o.secret, o.genre, qui=qui, origine="lan")
    if not ok:
        _echecs[qui].append(time.monotonic())
        raise HTTPException(403, "refusé")
    _echecs.pop(qui, None)
    return COFFRE.etat()


# ── racine : coffrectl, pour root ─────────────────────────────────────────────
racine = FastAPI(title="SecuBox Coffre (racine)", version=VERSION, docs_url=None, redoc_url=None,
                 openapi_url=None)
_routes_communes(racine, [])


@racine.post("/initialiser")
def initialiser(p: Phrase):
    return {"codes": _appel(COFFRE.initialiser, p.phrase)}


@racine.post("/ouvrir")
def ouvrir_racine(o: Ouverture):
    if not _appel(COFFRE.ouvrir, o.secret, o.genre, qui="root", origine="console"):
        raise HTTPException(403, "refusé")
    return COFFRE.etat()


@racine.get("/secrets/{compartiment}/{nom}/valeur")
def lire(compartiment: str, nom: str):
    return {"valeur": _appel(COFFRE.lire, compartiment, nom).decode("utf-8", "replace")}


@racine.post("/serrures/phrase")
def serrure_phrase(p: Phrase):
    return {"id": _appel(COFFRE.ajouter_serrure_phrase, p.phrase, p.libelle)}


@racine.delete("/serrures/{ident}")
def serrure_retirer(ident: str):
    _appel(COFFRE.retirer_serrure, ident)
    return {"retiree": True}


@racine.post("/serrures/secours")
def codes():
    return {"codes": _appel(COFFRE.regenerer_codes)}


@racine.post("/compartiments")
def compartiment(c: Compartiment):
    _appel(COFFRE.creer_compartiment, c.id, c.libelle)
    return {"cree": True}


# Compatibilité : `api.main:app` désigne la face publique.
app = public
