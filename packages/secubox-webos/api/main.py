# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
import asyncio
import json
import time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, Depends, Request

from secubox_core.auth import require_jwt
from secubox_core.health import systemd_batch
from api.models import Service
from api import registry, flags, cardlets, acces

_cache: dict = {"services": [], "computed_at": None}
_flags: dict = flags.load_flags()
_CACHE_FILE = Path("/var/cache/secubox/webos/services.json")


def _live_sockets(sock_dir: str = "/run/secubox") -> frozenset:
    """Ids joignables via socket (agrégateur ou daemon propre) — signal de santé."""
    try:
        return frozenset(p.stem for p in Path(sock_dir).glob("*.sock"))
    except Exception:
        return frozenset()


def _recompute() -> None:
    """Read menu/health/exposure sources and refresh `_cache` in place."""
    menu = registry.load_menu_cache()
    health = systemd_batch()
    expo = registry.load_exposure_cache()
    svcs = registry.normalize_services(menu, health, expo, sockets=_live_sockets())
    _cache["services"] = [s.model_dump() for s in svcs]
    _cache["computed_at"] = time.time()
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_cache))
    except Exception:
        pass


async def _refresh_loop() -> None:
    while True:
        try:
            _recompute()
        except Exception:
            pass
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _flags
    _flags = flags.load_flags()
    if _CACHE_FILE.exists():
        try:
            _cache.update(json.loads(_CACHE_FILE.read_text()))
        except Exception:
            pass
    task = asyncio.create_task(_refresh_loop())
    yield
    task.cancel()


app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos", lifespan=lifespan)
public_router = APIRouter(prefix="/public")
router = APIRouter()


def _enabled() -> bool:
    return bool(_flags.get("enabled"))


_PUBLIC_FIELDS = ("id", "name", "description", "category", "icon", "installed", "active")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@public_router.get("/services")
async def public_services():
    """Minimal, unauthenticated projection — never leaks urls/latency/reach."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    out = []
    for s in _cache["services"]:
        row = {k: s[k] for k in _PUBLIC_FIELDS if k in s}
        row["health"] = {"state": (s.get("health") or {}).get("state", "unknown")}
        # `path` (relatif, non sensible) : nécessaire pour construire l'URL de la
        # webui admin embarquée (admin.gk2.secubox.in<path>) côté Hall (#1175).
        row["path"] = (s.get("urls") or {}).get("path") or ("/" + s["id"] + "/")
        out.append(row)
    return {"services": out, "computed_at": _cache["computed_at"]}


_rc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/radio")
async def cardlet_radio():
    """Cardlet Radio (now-playing) — lue côté serveur via radio.sock, cache 5 s."""
    now = time.time()
    if _rc["d"] and now - _rc["t"] < 5:
        return _rc["d"]
    # radio_cardlet_safe fait de l'I/O socket BLOQUANTE : hors du thread, elle
    # gèle la boucle uvicorn (single-worker) → 502 sur tout le module (#1175).
    d = await asyncio.to_thread(cardlets.radio_cardlet_safe)
    _rc["d"], _rc["t"] = d, now
    return d


# Cardlets DISPONIBLES (#1231). Le Hall demandait ses cardlets par une liste
# ecrite en dur dans sa page : chaque nouveau cardlet obligeait a la modifier.
# Il decouvre desormais ce qui existe. Ajouter un cardlet = une entree ici, et
# l'accueil s'en saisit sans qu'on y touche.
CARDLETS_DISPONIBLES = ["radio", "waf", "podcaster"]


@public_router.get("/cardlets")
async def cardlets_index():
    """Liste des cardlets servis, pour que l'accueil les decouvre."""
    return {"cardlets": CARDLETS_DISPONIBLES, "count": len(CARDLETS_DISPONIBLES)}


_wc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/waf")
async def cardlet_waf():
    """Cardlet WAF (posture) — lue côté serveur via waf.sock, cache 20 s (#1228).

    Cache PLUS LONG que celui de la Radio : un now-playing change de titre en
    trois minutes, une posture de pare-feu bouge en dizaines de minutes.
    Interroger trois points d'entrée toutes les cinq secondes chargerait la box
    pour montrer le même chiffre — c'est exactement le travers qu'on vient de
    corriger ailleurs (#1210).
    """
    now = time.time()
    if _wc["d"] and now - _wc["t"] < 20:
        return _wc["d"]
    # Comme la Radio : l'I/O socket est BLOQUANTE, elle gèlerait la boucle
    # uvicorn mono-ouvrier et rendrait 502 tout le module (#1175).
    d = await asyncio.to_thread(cardlets.waf_cardlet_safe)
    _wc["d"], _wc["t"] = d, now
    return d


_pc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/podcaster")
async def cardlet_podcaster():
    """Cardlet Podcaster (bibliothèque) — lue via podcaster.sock, cache 30 s.

    Cache le plus long des trois : un épisode arrive toutes les heures au mieux.
    Interroger plus souvent afficherait le même titre en chargeant la box.
    """
    now = time.time()
    if _pc["d"] and now - _pc["t"] < 30:
        return _pc["d"]
    d = await asyncio.to_thread(cardlets.podcaster_cardlet_safe)
    _pc["d"], _pc["t"] = d, now
    return d


_mbbs = {"d": None, "t": 0.0}


@public_router.get("/menu/bbs")
async def menu_bbs():
    """Sous-menu BBS (rubriques) — « navbar embarquée » lue via bbs.sock, cache 30 s."""
    now = time.time()
    if _mbbs["d"] and now - _mbbs["t"] < 30:
        return _mbbs["d"]
    d = await asyncio.to_thread(cardlets.bbs_menu_safe)
    _mbbs["d"], _mbbs["t"] = d, now
    return d


@router.get("/services")
async def services(user=Depends(require_jwt)):
    """Full registry — JWT-gated."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    return {"services": _cache["services"], "computed_at": _cache["computed_at"]}


# ── DÉLÉGATION D'ACCÈS (#1288) ─────────────────────────────────────────────
#
# Deux routes PUBLIQUES, et elles le sont a dessein : une carte doit pouvoir
# demander si elle a un acces, et en deposer la demande. Ni l'une ni l'autre ne
# revele quoi que ce soit — la premiere rend deux booleens, la seconde inscrit
# une ligne dans une file bornee. Tout ce qui accorde, lit ou pose un secret est
# derriere le jeton.

@public_router.get("/acces/{svc}")
async def acces_etat(svc: str):
    return acces.etat(svc)


@public_router.post("/acces/{svc}/demande")
async def acces_demande(svc: str, request: Request):
    # L'origine est notee pour que l'operateur sache d'ou vient la demande —
    # une file qui ne dit pas qui a demande ne se valide pas serieusement.
    return acces.depose(svc, request.headers.get("referer", ""))


@router.get("/acces")
async def acces_liste(user=Depends(require_jwt)):
    """Ce que la console doit montrer : les demandes en attente, et les acces
    deja accordes. JAMAIS les secrets."""
    return {
        "demandes": acces.demandes(),
        "accordes": [
            {"svc": k, "nom": v["nom"], "hote": v["hote"], "flux": v["flux"],
             "acces": acces.a_acces(k)}
            for k, v in acces.SERVICES.items()
        ],
    }


@router.post("/acces/{svc}/valider")
async def acces_valider(svc: str, user=Depends(require_jwt)):
    """Demarre le flux de delegation et rend l'URL a ouvrir. Le mot de passe
    sera tape DANS le service, jamais ici."""
    return await acces.flux_demarre(svc)


@router.post("/acces/{svc}/sonde")
async def acces_sonde(svc: str, user=Depends(require_jwt)):
    return await acces.flux_sonde(svc)


@router.post("/acces/{svc}/manuel")
async def acces_manuel(svc: str, corps: dict, user=Depends(require_jwt)):
    """Identifiant dedie pour les services sans flux de delegation. Route sous
    jeton : le secret ne transite que vers une page authentifiee."""
    return acces.pose_manuel(svc, str(corps.get("compte") or ""),
                             str(corps.get("secret") or ""))


@router.delete("/acces/{svc}")
async def acces_revoque(svc: str, user=Depends(require_jwt)):
    return acces.revoque(svc)


app.include_router(public_router)
app.include_router(router)
