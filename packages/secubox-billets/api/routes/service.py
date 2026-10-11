# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Route de SERVICE pour les billets éphémères (#2268).

MetaNews publie des billets à vie limitée (5 minutes) : il n'a pas de session d'exploitant, et il ne doit pas en avoir. Cette route lui donne exactement
ce dont il a besoin et rien de plus :

  - un jeton de flotte (JWT HS256, `api.jwt_secret`) dont le `sub` est dans SERVICES — pas un jeton d'usager ;
  - elle ne crée QUE des billets éphémères : `ttl_s` obligatoire, 30 s à 1 h. Jamais de billet durable, ni modification, ni suppression ;
  - un plafond horaire côté billets, quoi que fasse l'appelant ;
  - INTERNE : un appel qui porte X-Real-IP ou X-Forwarded-For est passé par nginx/le WAF, donc vient de l'extérieur — refusé. MetaNews parle directement
    à la socket Unix.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .. import repo
from ..models import BilletIn

SERVICES = frozenset({"metanews"})
PLAFOND_HORAIRE = 60
TTL_MAX = 3600


class EphemereIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str
    ref_url: Optional[str] = None
    embed_url: Optional[str] = None
    vignette_url: Optional[Annotated[str, Field(pattern=r"^https://\S{1,480}$")]] = None
    ttl_s: Annotated[int, Field(ge=30, le=TTL_MAX)]


def _jeton(request: Request) -> dict:
    ent = request.headers.get("authorization", "")
    if not ent.lower().startswith("bearer ") or len(ent) < 20:
        raise HTTPException(401, "jeton de service requis")
    try:
        import jwt
        from secubox_core.auth import _secret
        return jwt.decode(ent[7:].strip(), _secret(), algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except Exception:  # noqa: BLE001 — signature, expiration, secret absent : le motif ne se détaille pas à l'appelant
        raise HTTPException(401, "jeton invalide")


async def _enrichir(request: Request, billet_id: str, embed_url: str, vignette_url: str | None = None) -> None:
    """#2343 — même résolution qu'un billet créé à la main : embed (oEmbed / carte OG) puis vignette locale.
    Les sites d'actualité refusent les robots : quand MetaNews fournit l'image de son flux (https), c'est elle qu'on
    rapatrie (SSRF-gardée, sans navigateur) au lieu d'une capture de page. Après la réponse, jamais bloquant."""
    import asyncio

    from . import admin
    from ..ids import new_ulid
    from ..services import snapshot, ssrf

    async def vignette():
        resolver = getattr(request.app.state, "resolver", ssrf._default_resolver)
        res = await asyncio.to_thread(snapshot.capture, embed_url, vignette_url, new_ulid(),
                                      resolver=resolver, enable_browser=False)
        if res:
            await repo.set_embed_snapshot(request.app.state.conn, billet_id, res[0])

    for etape in (lambda: admin._resolve_and_store_embed(request, billet_id, embed_url),
                  vignette if vignette_url else lambda: admin._maybe_capture_snapshot(request, billet_id, embed_url, "communique")):
        try:
            await etape()
        except Exception:  # noqa: BLE001 — l'aperçu est un bonus
            pass


def register_service(app: FastAPI) -> None:
    @app.post("/service/ephemere", status_code=201)
    async def creer_ephemere(request: Request, payload: EphemereIn, taches: BackgroundTasks):
        if request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for"):
            raise HTTPException(403, "route interne : appel direct sur la socket uniquement")
        claims = _jeton(request)
        if claims.get("sub") not in SERVICES:
            raise HTTPException(403, "service non autorisé")
        try:
            data = BilletIn(body=payload.body, ref_url=payload.ref_url, embed_url=payload.embed_url, publish=True, ttl_s=payload.ttl_s)
        except ValidationError as exc:
            raise HTTPException(422, f"billet invalide : {exc.errors()}")
        conn = request.app.state.conn
        il_y_a_une_heure = repo._plus_secondes(repo._maintenant(), -3600)
        async with conn.execute("SELECT COUNT(*) FROM billet WHERE expires_at IS NOT NULL AND published_at >= ?", (il_y_a_une_heure,)) as cur:
            if (await cur.fetchone())[0] >= PLAFOND_HORAIRE:
                raise HTTPException(429, "plafond horaire de billets éphémères atteint")
        billet_id = await repo.create_billet(conn, data, now=repo._maintenant())
        row = await repo.get_by_id(conn, billet_id)
        if data.embed_url:
            taches.add_task(_enrichir, request, billet_id, data.embed_url, payload.vignette_url)
        return {"id": row["id"], "slug": row["slug"], "expires_at": row["expires_at"], "published_at": row["published_at"]}
