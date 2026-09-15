# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: routes du profileur — invitation et profils (#1297).

DEUX SURFACES, ET ELLES N'ONT RIEN À VOIR :

  • `/invitation/*` — OUVERTE. C'est la seule porte de tout SecuBox qui accepte
    un inconnu, parce qu'il faut bien un premier contact. Elle ne fait que deux
    choses : recevoir une demande, et rendre l'état d'une demande à qui détient
    son jeton de suivi.

  • `/invitations/*` — ADMIN. La file, la validation, la promotion.

CE QU'UNE PORTE OUVERTE IMPOSE. La box voit passer des dizaines de milliers de
sondes par jour. Cette route est donc bornée : une demande par appareil, un
plafond par adresse, un corps de taille limitée, et rien qui distingue un DID
inconnu d'un DID refusé — sinon la route devient un moyen d'énumérer qui a
accès.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt

from .invitations import (PROFILS, DemandeInvalide, Profileur)

log = logging.getLogger("secubox.users.invitations")

FICHIER = Path("/var/lib/secubox/users/invitations.json")

#: Plafond par adresse. Volontairement bas : une demande d'accès est un geste
#: humain, pas une boucle. Cinq essais laissent de la place aux hésitations
#: (formulaire mal rempli, nom refusé) sans ouvrir la porte à un remplissage.
PLAFOND_PAR_IP = 5
FENETRE_S = 3600

router = APIRouter()
_profileur: Optional[Profileur] = None
_compteur: dict[str, list[float]] = {}


def profileur() -> Profileur:
    """Construit le profileur au premier usage.

    LA CRÉATION DE COMPTE EST INJECTÉE ICI, et c'est le seul endroit qui relie
    l'admission à `secubox-users` : le profileur décide, le moteur exécute.
    """
    global _profileur
    if _profileur is None:
        def creer(nom: str, profil: str, did: str) -> None:
            try:
                from . import engine as moteur
                moteur.create_user_if_absent(nom, profil=profil, did=did)
            except (ImportError, AttributeError):
                # Le moteur n'expose pas encore ce point d'entrée : on
                # l'ÉCRIT plutôt que d'échouer l'admission. La demande est
                # acceptée, le compte reste à créer — et ça se voit.
                log.warning("admission de %s (profil %s, %s) enregistrée, "
                            "compte à créer à la main : engine ne fournit pas "
                            "create_user_if_absent", nom, profil, did)
        _profileur = Profileur(FICHIER, creer_compte=creer)
    return _profileur


def _cadence(req: Request) -> None:
    """Plafonne les demandes par adresse. Lève 429 au-delà."""
    ip = (req.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (req.client.host if req.client else "?"))
    maintenant = time.monotonic()
    essais = [t for t in _compteur.get(ip, []) if maintenant - t < FENETRE_S]
    if len(essais) >= PLAFOND_PAR_IP:
        raise HTTPException(429, "Trop de demandes. Réessayez plus tard.")
    essais.append(maintenant)
    _compteur[ip] = essais


# ─────────────────────────────────────────────────────────────────────────────
# Surface OUVERTE
# ─────────────────────────────────────────────────────────────────────────────

class DemandeIn(BaseModel):
    """Le formulaire. Inscription, invitation et demande d'accès à la fois."""
    did: str = Field(max_length=160)
    cle_publique: str = Field(max_length=64)
    nom: str = Field(max_length=60)
    message: str = Field(default="", max_length=500)
    appareil: str = Field(default="", max_length=60)


@router.post("/invitation/demande")
async def demander(corps: DemandeIn, req: Request):
    """Déposer une demande d'accès. **Non authentifié — c'est le but.**"""
    _cadence(req)
    try:
        d = profileur().demande(corps.model_dump())
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e

    if d.etat == "acceptee":
        # Déjà admis : on le dit, sans jeton (il n'en a plus besoin).
        return {"etat": "acceptee", "profil": d.profil, "empreinte": d.empreinte}

    log.info("demande d'accès : %s (%s) — empreinte %s",
             d.nom, d.appareil, d.empreinte)
    return {
        "etat": d.etat,
        # Le jeton de suivi n'est rendu QU'ICI, une fois : c'est avec lui que le
        # client sondera sans être authentifié.
        "jeton": d.jeton,
        # L'empreinte s'affiche côté client pour que l'administrateur la
        # compare — c'est le remplaçant du QR code.
        "empreinte": d.empreinte,
    }


@router.get("/invitation/suivi")
async def suivi(did: str, jeton: str):
    """Où en est MA demande. Non authentifié, mais il faut le jeton."""
    vue = profileur().suivi(did, jeton)
    if vue is None:
        # MÊME RÉPONSE pour « inconnu » et « mauvais jeton ». Les distinguer
        # ferait de cette route un moyen de savoir quels appareils ont demandé.
        raise HTTPException(404, "Demande introuvable.")
    return vue


# ─────────────────────────────────────────────────────────────────────────────
# Surface ADMIN
# ─────────────────────────────────────────────────────────────────────────────

class Verdict(BaseModel):
    did: str
    motif: str = Field(default="", max_length=200)
    profil: str = "user"


@router.get("/invitations", dependencies=[Depends(require_jwt)])
async def file_attente():
    """Les demandes à trancher, avec leur empreinte."""
    return {"en_attente": profileur().en_attente()}


@router.post("/invitations/accepter", dependencies=[Depends(require_jwt)])
async def accepter(v: Verdict, req: Request):
    try:
        d = profileur().accepte(v.did, par=_qui(req), profil=v.profil)
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did, "profil": d.profil}


@router.post("/invitations/refuser", dependencies=[Depends(require_jwt)])
async def refuser(v: Verdict, req: Request):
    try:
        d = profileur().refuse(v.did, par=_qui(req), motif=v.motif)
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did}


@router.post("/invitations/promouvoir", dependencies=[Depends(require_jwt)])
async def promouvoir(v: Verdict, req: Request):
    """Changer le profil d'un admis. C'est ICI, et nulle part ailleurs, que
    `admin` devient possible."""
    if v.profil not in PROFILS:
        raise HTTPException(400, f"profil inconnu : {v.profil}")
    try:
        d = profileur().promeut(v.did, vers=v.profil, par=_qui(req))
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    log.info("profil de %s porté à %s par %s", d.did, d.profil, d.traitee_par)
    return {"ok": True, "did": d.did, "profil": d.profil}


@router.post("/invitations/revoquer", dependencies=[Depends(require_jwt)])
async def revoquer(v: Verdict, req: Request):
    try:
        d = profileur().revoque(v.did, par=_qui(req))
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did}


def _qui(req: Request) -> str:
    """Qui a tranché. On le note pour que la file garde une responsabilité."""
    u = getattr(req.state, "user", None)
    return str(getattr(u, "username", None) or u or "admin")
