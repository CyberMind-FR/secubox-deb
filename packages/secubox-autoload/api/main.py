# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: le SERVICE d'enrôlement et le PANEL (#2190, parent #2182)

Deux applications, trois preuves :

  portée « public » (socket Unix, derrière HAProxy → sbxwaf → nginx)
    PUBLIQUE, preuve = le jeton     POST /enrol   (la seule route sans garde : le jeton à usage unique EST la preuve, refus uniforme, essais limités)
    ADMIN, preuve = administrateur  lecture : require_lecture ; écriture : require_jwt (émission, révocation, abonnement, refus de pré-rapport)

  portée « tunnel » (TCP 10.64.0.1:8470, UNIQUEMENT à l'intérieur de WireGuard)
    BOX, preuve = l'adresse du tunnel   POST /progression, POST /prerapport, GET /prerapport/{empreinte}/refus
    L'identité est l'adresse SOURCE de la connexion TCP : WireGuard ne laisse passer, d'un pair, que les paquets dont la source est SON adresse
    (AllowedIPs), donc elle ne se falsifie pas et aucun en-tête n'est cru. Une adresse hors plage, inconnue ou retirée n'a aucun droit.
    Les routes de box n'existent PAS dans l'application publique (404) : un en-tête forgé de l'extérieur n'ouvre rien.

Le service n'est pas root : il écrit le pair, puis demande à l'unité root `autoloadctl tunnel-sync` (par fichier) de l'appliquer, et attend son accusé.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Callable, Dict, List, Literal, Optional

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from secubox_core.auth import require_jwt, require_lecture

from autoload import jetons as J, tunnel as T

PREFIXE = "/api/v1/autoload"
CORPS_MAX = 128 * 1024
ESSAIS_MAX = 10
FENETRE_S = 600


class Limiteur:
    """Au plus ESSAIS_MAX réclamations refusées par adresse source et par FENETRE_S ; passé ce cap, même le bon jeton attend."""

    def __init__(self, horloge: Callable[[], float] = time.time):
        self._h, self._echecs = horloge, {}

    def bloque(self, ip: str) -> bool:
        maintenant = self._h()
        recents = [t for t in self._echecs.get(ip, []) if maintenant - t < FENETRE_S]
        self._echecs[ip] = recents
        return len(recents) >= ESSAIS_MAX

    def echec(self, ip: str) -> None:
        self._echecs.setdefault(ip, []).append(self._h())
        if len(self._echecs) > 10000:                                      # mémoire bornée : on oublie les sources les plus anciennes
            for k in sorted(self._echecs, key=lambda k: max(self._echecs[k] or [0]))[:5000]:
                self._echecs.pop(k, None)


class EnrolIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jeton: Optional[str] = Field(default=None, max_length=64)
    serie: Optional[str] = Field(default=None, max_length=64)
    cle_pub: str = Field(min_length=44, max_length=44)

    @model_validator(mode="after")
    def _un_seul(self):
        if (self.jeton is None) == (self.serie is None):
            raise ValueError("un jeton OU un numéro de série")
        return self


class EmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client: str = Field(max_length=40)
    profil: str = Field(max_length=40)
    lot: Optional[str] = Field(default=None, max_length=40)
    serie: Optional[str] = Field(default=None, max_length=64)
    duree_jours: int = Field(default=J.DUREE_DEFAUT_S // 86400, ge=1, le=J.DUREE_MAX_S // 86400)


class SerieIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    serie: str = Field(max_length=64)
    client: str = Field(max_length=40)
    profil: str = Field(max_length=40)
    lot: Optional[str] = Field(default=None, max_length=40)


class MotifIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    motif: str = Field(max_length=200)


class AbonnementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statut: Literal["actif", "suspendu", "revoque"]
    mois: Optional[int] = Field(default=None, ge=1, le=120)
    formule: Optional[str] = Field(default=None, max_length=30)


class ProgressionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    etape: str = Field(max_length=40)
    faites: int = Field(ge=0, le=100)
    total: int = Field(ge=1, le=100)
    termine: bool = False


def ip_source(request: Request) -> str:
    """L'adresse du client telle que la chaîne amont (sbxwaf, nginx) la transmet : le dernier saut de X-Forwarded-For qui n'est pas la boucle locale.
    Sert à LIMITER les essais, jamais à autoriser quoi que ce soit."""
    sauts = [x.strip() for x in request.headers.get("x-forwarded-for", "").split(",") if x.strip()]
    while sauts and sauts[-1] in ("127.0.0.1", "::1"):
        sauts.pop()
    return (sauts[-1] if sauts else (request.client.host if request.client else "?"))[:45]


async def _borne_corps(request: Request) -> None:
    taille = request.headers.get("content-length")
    if taille is not None and taille.isdigit() and int(taille) > CORPS_MAX:
        raise HTTPException(413, "corps trop gros")


def _routes_box(r: APIRouter, reg: J.Registre, garde_tunnel) -> None:
    @r.post("/progression", dependencies=[Depends(_borne_corps)])
    def progression(corps: ProgressionIn, cle: str = Depends(garde_tunnel)):
        try:
            reg.noter_progression(cle, corps.etape, corps.faites, corps.total, corps.termine)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        return {"ok": True}

    @r.post("/prerapport", dependencies=[Depends(_borne_corps)])
    def prerapport(corps: Dict = Body(...), cle: str = Depends(garde_tunnel)):
        try:
            return {"empreinte": reg.recevoir_prerapport(cle, corps)}
        except ValueError as e:
            raise HTTPException(422, str(e)) from None

    @r.get("/prerapport/{empreinte}/refus")
    def refus(empreinte: str, cle: str = Depends(garde_tunnel)):
        return {"refuse": reg.prerapport_refuse(empreinte[:64], cle)}



def creer_app(reg: J.Registre, pairs: T.Pairs, cle_hub_pub: str, appliquer: Callable[[], None], horloge: Callable[[], float] = time.time,
              portee: Literal["public", "tunnel"] = "public") -> FastAPI:
    app = FastAPI(title="secubox-autoload", docs_url=None, redoc_url=None, openapi_url=None)
    r = APIRouter(prefix=PREFIXE)
    limiteur = Limiteur(horloge)

    def garde_tunnel(request: Request) -> str:
        """La clé publique de la box qui parle, d'après l'adresse SOURCE de la connexion (WireGuard ne laisse passer que la sienne). Tout le reste est 401."""
        try:
            ip = ipaddress.IPv4Address(request.client.host if request.client else "")
        except ValueError:
            raise HTTPException(401, "identité de tunnel absente") from None
        if ip not in ipaddress.ip_network(T.RESEAU) or str(ip) == T.HUB:
            raise HTTPException(401, "identité de tunnel refusée")
        for p in pairs.actifs():
            if p["adresse"] == str(ip):
                return p["cle_pub"]
        raise HTTPException(401, "identité de tunnel refusée")

    @r.get("/health")
    def sante():
        return {"ok": True}

    if portee == "tunnel":
        _routes_box(r, reg, garde_tunnel)
        app.include_router(r)
        return app

    # ── publique : le jeton est la preuve ─────────────────────────────────────────────────────────────────────
    @r.post("/enrol", dependencies=[Depends(_borne_corps)])
    def enroler(corps: EnrolIn, request: Request):
        ip = ip_source(request)
        if limiteur.bloque(ip):
            raise HTTPException(429, "trop d'essais")
        try:
            rec = reg.reclamer(corps.jeton, corps.cle_pub) if corps.jeton is not None else reg.reclamer_par_serie(corps.serie, corps.cle_pub)
            adresse = pairs.attribuer(corps.cle_pub)
        except (J.JetonRefuse, ValueError):
            limiteur.echec(ip)
            raise HTTPException(403, "jeton refusé") from None
        except T.PlageEpuisee:
            raise HTTPException(503, "service indisponible") from None
        try:
            appliquer()
        except T.TunnelErreur as e:
            reg._audit("tunnel-echec", f"client={rec.client} : {e}")                  # la raison reste côté serveur ; la box ne reçoit que « indisponible »
            raise HTTPException(503, "service indisponible") from None                # le jeton reste réclamé : la même box peut rejouer
        return {"client": rec.client, "profil": rec.profil, "lot": rec.lot, "tunnel": T.gabarit_box(adresse, cle_hub_pub)}

    # ── administration : lecture ──────────────────────────────────────────────────────────────────────────────
    @r.get("/boxes", dependencies=[Depends(require_lecture)])
    def boxes():
        return reg.boxes()

    @r.get("/jetons", dependencies=[Depends(require_lecture)])
    def jetons():
        return [{k: v for k, v in x.items() if k != "cle_pub"} for x in reg.lister()]            # jamais la valeur, jamais l'empreinte, pas la clé

    @r.get("/prerapports", dependencies=[Depends(require_lecture)])
    def prerapports():
        return reg.prerapports()

    @r.get("/prerapports/{empreinte}", dependencies=[Depends(require_lecture)])
    def un_prerapport(empreinte: str):
        pre = reg.prerapport(empreinte[:64])
        if pre is None:
            raise HTTPException(404, "pré-rapport inconnu")
        return pre

    # ── administration : écriture ─────────────────────────────────────────────────────────────────────────────
    @r.post("/jetons", dependencies=[Depends(require_jwt)])
    def emettre(corps: EmissionIn):
        try:
            e = reg.emettre(corps.client, corps.profil, lot=corps.lot, serie=corps.serie, duree_s=corps.duree_jours * 86400)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return {"id": e.id, "valeur": e.valeur, "expire_le": e.expire_le}                      # la valeur n'est montrée QU'ICI

    @r.post("/series", dependencies=[Depends(require_jwt)])
    def preenregistrer(corps: SerieIn):
        try:
            reg.preenregistrer(corps.serie, corps.client, corps.profil, lot=corps.lot)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        except Exception as err:                                                               # série déjà préenregistrée (clé primaire)
            raise HTTPException(409, "série déjà préenregistrée") from err
        return {"ok": True}

    @r.post("/jetons/{ident}/revoquer", dependencies=[Depends(require_jwt)])
    def revoquer(ident: int, corps: MotifIn):
        try:
            cle = reg.revoquer(ident, corps.motif)
        except ValueError:
            raise HTTPException(404, "jeton inconnu") from None
        applique = True
        if pairs.retirer(cle):
            try:
                appliquer()
            except T.TunnelErreur:
                applique = False
        return {"revoque": True, "tunnel_applique": applique}

    @r.post("/clients/{client}/abonnement", dependencies=[Depends(require_jwt)])
    def abonnement(client: str, corps: AbonnementIn):
        try:
            expire = J.ajouter_mois(int(horloge()), corps.mois) if corps.mois else None
            n = reg.fixer_abonnement(client, corps.statut, expire_le=expire, formule=corps.formule)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return {"jetons": n, "expire_le": expire}

    @r.post("/prerapports/{empreinte}/refuser", dependencies=[Depends(require_jwt)])
    def refuser(empreinte: str, corps: MotifIn):
        try:
            reg.refuser_prerapport(empreinte[:64], corps.motif)
        except ValueError:
            raise HTTPException(404, "pré-rapport inconnu") from None
        return {"refuse": True}

    app.include_router(r)
    return app
