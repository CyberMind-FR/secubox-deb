# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: le SERVICE d'enrôlement et le PANEL (#2190, parent #2182)

Deux applications, trois preuves :

  portée « public » (socket Unix ; l'agrégateur relaie /api/v1/autoload/… en retirant le préfixe, derrière HAProxy → sbxwaf → nginx)
    PUBLIQUE, preuve = le jeton     POST /enrol   (la seule route sans garde : le jeton à usage unique EST la preuve, refus uniforme, essais limités)
    ADMIN, preuve = administrateur  lecture ET écriture : require_jwt (l'identité des clients et leurs pré-rapports ne se lisent pas en « mode tableau de bord LAN »)

  portée « tunnel » (TCP 10.64.0.1:8470, UNIQUEMENT à l'intérieur de WireGuard)
    BOX, preuve = l'adresse du tunnel   POST /progression, POST /prerapport, GET /prerapport/{empreinte}/refus
    L'identité est l'adresse SOURCE de la connexion TCP : WireGuard ne laisse passer, d'un pair, que les paquets dont la source est SON adresse
    (AllowedIPs), donc elle ne se falsifie pas et aucun en-tête n'est cru. Une adresse hors plage, inconnue ou retirée n'a aucun droit.
    Les routes de box n'existent PAS dans l'application publique (404) : un en-tête forgé de l'extérieur n'ouvre rien.

Le service n'est pas root : il écrit le pair, puis demande `autoloadctl tunnel-sync` par sudo à argv exact (sudoers du paquet) et attend son code
de retour. tunnel-sync applique les pairs puis réexporte la projection publique lue par le maître de pilotage (#3126) : TOUT changement d'abonnement
ou révocation le relance (R37), et une minuterie horaire du service le relance aussi (échéance passée → `echu`).
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Callable, Dict, Literal, Optional

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from secubox_core.auth import require_jwt

from autoload import jetons as J, tunnel as T

PREFIXE = ""          # les routes sont à la racine : l'agrégateur sert /api/v1/autoload/… en retirant le préfixe (convention de la plateforme)
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


class FormuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nom: str = Field(max_length=30)
    libelle: str = Field(max_length=60)
    profil: str = Field(max_length=40)
    mois: int = Field(ge=1, le=120)


class ProlongerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mois: int = Field(ge=1, le=120)


class ChangerFormuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    formule: str = Field(max_length=30)


class RepriseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    motif: Optional[str] = Field(default=None, max_length=200)


class RevocationBoxIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    motif: str = Field(max_length=200)
    confirmation: str = Field(max_length=64)


PROFILS_APPLIQUES = Path("/var/lib/secubox/pilotage-public/profils-appliques.json")
PROFILS_APPLIQUES_MAX = 256 * 1024
_ADRESSE = re.compile(r"^10\.64\.\d{1,3}\.\d{1,3}$")


def lire_profils_appliques(chemin: Path) -> Dict[str, str]:
    """Relevé facultatif du pilotage (#3303) : `{"version": 1, "boxes": [{"adresse": "10.64.x.y", "profil": "<profil réel>"}]}`.
    Absent, illisible, trop gros ou mal formé → {} (profil appliqué inconnu, jamais un écart inventé). Toute entrée hors forme est ignorée."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(PROFILS_APPLIQUES_MAX + 1)
        if len(brut) > PROFILS_APPLIQUES_MAX:
            return {}
        donnees = json.loads(brut)
    except (OSError, ValueError):
        return {}
    sortie: Dict[str, str] = {}
    if not isinstance(donnees, dict) or donnees.get("version") != 1 or not isinstance(donnees.get("boxes"), list):
        return {}
    for b in donnees["boxes"]:
        if isinstance(b, dict) and isinstance(b.get("adresse"), str) and _ADRESSE.match(b["adresse"]) and b.get("profil") in J.PROFILS:
            sortie[b["adresse"]] = b["profil"]
    return sortie


class ContactIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Optional[str] = Field(default=None, max_length=254)


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


def _routes_box(r: APIRouter, reg: J.Registre, garde_tunnel, courrier: Optional[Callable[[Dict, str], None]] = None) -> None:
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

    @r.post("/rapport", dependencies=[Depends(_borne_corps)])
    def rapport(corps: Dict = Body(...), cle: str = Depends(garde_tunnel)):
        try:
            ident = reg.recevoir_rapport(cle, corps)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        envoye = False
        contact = reg.contact(corps["client"])
        if courrier is not None and contact:
            try:
                courrier(corps, contact)
                reg.marquer_rapport_envoye(ident)
                envoye = True
            except Exception as e:  # noqa: BLE001 — SMTP, réseau, adresse : le rapport est déjà conservé, la box n'a pas à en pâtir
                reg._audit("rapport-mail-echec", f"rapport={ident} : {type(e).__name__}")
        return {"ok": True, "envoye": envoye}

    @r.get("/prerapport/{empreinte}/refus")
    def refus(empreinte: str, cle: str = Depends(garde_tunnel)):
        return {"refuse": reg.prerapport_refuse(empreinte[:64], cle)}



def creer_app(reg: J.Registre, pairs: T.Pairs, cle_hub_pub: str, appliquer: Callable[[], None], horloge: Callable[[], float] = time.time,
              portee: Literal["public", "tunnel"] = "public", courrier: Optional[Callable[[Dict, str], None]] = None,
              publier_tunnel: Optional[Callable[[], None]] = None, profils_appliques: Path = PROFILS_APPLIQUES) -> FastAPI:
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
        _routes_box(r, reg, garde_tunnel, courrier)
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
            reg._audit("tunnel-echec", f"client={rec.client} : {str(e)[-240:]}")                  # la raison reste côté serveur ; la box ne reçoit que « indisponible »
            raise HTTPException(503, "service indisponible") from None                # le jeton reste réclamé : la même box peut rejouer
        return {"client": rec.client, "profil": rec.profil, "lot": rec.lot, "tunnel": T.gabarit_box(adresse, cle_hub_pub)}

    # ── administration : lecture ──────────────────────────────────────────────────────────────────────────────
    @r.get("/boxes", dependencies=[Depends(require_jwt)])
    def boxes():
        return reg.boxes()

    @r.get("/jetons", dependencies=[Depends(require_jwt)])
    def jetons():
        return [{k: v for k, v in x.items() if k != "cle_pub"} for x in reg.lister()]            # jamais la valeur, jamais l'empreinte, pas la clé

    @r.get("/prerapports", dependencies=[Depends(require_jwt)])
    def prerapports():
        return reg.prerapports()

    @r.get("/prerapports/{empreinte}", dependencies=[Depends(require_jwt)])
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

    republier = publier_tunnel or appliquer

    def publier() -> bool:
        """tunnel-sync --sans-reactiver (argv sudo exact) : applique les pairs ET réexporte la projection publique lue par le maître de pilotage
        (#3126, R37), sans jamais relancer un wg-autoload dont l'exploitant a désactivé l'unité (relecture de la tâche 0, Minor 3 ; seul
        l'enrôlement monte l'interface). Faux si le système refuse : le changement reste enregistré, la minuterie horaire du service republiera."""
        try:
            republier()
            return True
        except T.TunnelErreur:
            return False

    @r.post("/jetons/{ident}/revoquer", dependencies=[Depends(require_jwt)])
    def revoquer(ident: int, corps: MotifIn):
        try:
            cle = reg.revoquer(ident, corps.motif)
        except ValueError:
            raise HTTPException(404, "jeton inconnu") from None
        pairs.retirer(cle)
        return {"revoque": True, "tunnel_applique": publier()}                                  # toujours : la projection change même sans pair

    @r.post("/lots/{lot}/revoquer", dependencies=[Depends(require_jwt)])
    def revoquer_lot(lot: str, corps: MotifIn):
        try:
            cles = reg.revoquer_lot_cles(lot, corps.motif)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        retires = sum(1 for c in cles if pairs.retirer(c))
        return {"revoque": True, "pairs_retires": retires, "tunnel_applique": publier()}

    @r.post("/clients/{client}/abonnement", dependencies=[Depends(require_jwt)])
    def abonnement(client: str, corps: AbonnementIn):
        try:
            expire = J.ajouter_mois(int(horloge()), corps.mois) if corps.mois else None
            n = reg.fixer_abonnement(client, corps.statut, expire_le=expire, formule=corps.formule)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return {"jetons": n, "expire_le": expire, "tunnel_applique": publier()}                # suspendu/revoque/echu atteint le maître (R37)

    # ── abonnements par box et formules (#3303) ──────────────────────────────────────────────────────────────
    @r.get("/formules", dependencies=[Depends(require_jwt)])
    def formules():
        return reg.formules()

    @r.post("/formules", dependencies=[Depends(require_jwt)])
    def fixer_formule(corps: FormuleIn):
        try:
            reg.fixer_formule(corps.nom, corps.libelle, corps.profil, corps.mois)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return {"ok": True}

    @r.get("/abonnements", dependencies=[Depends(require_jwt)])
    def abonnements():
        return [{k: v for k, v in x.items() if k != "adresse"} for x in reg.abonnements(lire_profils_appliques(profils_appliques))]

    def sur_box(faire):
        try:
            res = faire()
        except LookupError:
            raise HTTPException(404, "box inconnue") from None
        except PermissionError as err:
            raise HTTPException(409, str(err)) from None
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return res

    @r.post("/boxes/{ident}/abonnement/prolonger", dependencies=[Depends(require_jwt)])
    def prolonger(ident: int, corps: ProlongerIn):
        expire = sur_box(lambda: reg.prolonger_box(ident, corps.mois))
        return {"expire_le": expire, "tunnel_applique": publier()}

    @r.post("/boxes/{ident}/abonnement/formule", dependencies=[Depends(require_jwt)])
    def changer_formule(ident: int, corps: ChangerFormuleIn):
        sur_box(lambda: reg.changer_formule_box(ident, corps.formule))
        return {"ok": True, "tunnel_applique": publier()}

    @r.post("/boxes/{ident}/abonnement/suspendre", dependencies=[Depends(require_jwt)])
    def suspendre(ident: int, corps: MotifIn):
        sur_box(lambda: reg.suspendre_box(ident, corps.motif))
        return {"ok": True, "tunnel_applique": publier()}

    @r.post("/boxes/{ident}/abonnement/reprendre", dependencies=[Depends(require_jwt)])
    def reprendre(ident: int, corps: RepriseIn):
        sur_box(lambda: reg.reprendre_box(ident, corps.motif))
        return {"ok": True, "tunnel_applique": publier()}

    @r.post("/boxes/{ident}/abonnement/revoquer", dependencies=[Depends(require_jwt)])
    def revoquer_box(ident: int, corps: RevocationBoxIn):
        cle = sur_box(lambda: reg.revoquer_box(ident, corps.motif, corps.confirmation))
        if cle:
            pairs.retirer(cle)
        return {"revoque": True, "tunnel_applique": publier()}

    @r.get("/rapports", dependencies=[Depends(require_jwt)])
    def rapports():
        return reg.rapports()

    @r.get("/rapports/{ident}", dependencies=[Depends(require_jwt)])
    def un_rapport(ident: int):
        rap = reg.rapport(ident)
        if rap is None:
            raise HTTPException(404, "rapport inconnu")
        return rap

    @r.post("/clients/{client}/contact", dependencies=[Depends(require_jwt)])
    def contact(client: str, corps: ContactIn):
        try:
            reg.fixer_contact(client, corps.email)
        except ValueError as err:
            raise HTTPException(422, str(err)) from None
        return {"ok": True}

    @r.post("/prerapports/{empreinte}/refuser", dependencies=[Depends(require_jwt)])
    def refuser(empreinte: str, corps: MotifIn):
        try:
            reg.refuser_prerapport(empreinte[:64], corps.motif)
        except ValueError:
            raise HTTPException(404, "pré-rapport inconnu") from None
        return {"refuse": True}

    app.include_router(r)
    return app
