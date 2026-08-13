# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""JWT-authed JSON admin surface for the SecuBox Companion.

The HTML admin (routes/admin.py) is gated by billets' own session login
(argon2id + TOTP + CSRF). This parallel JSON surface lets the SecuBox Companion —
which carries a SecuBox JWT / parent-domain `secubox_session` cookie — create
billets, upload media, and moderate comments, reusing the SAME repo/media layer.

Auth is `secubox_core.auth.require_jwt` (accepts the Bearer token OR the session
cookie). If secubox_core is unavailable (isolated unit tests), the surface is not
registered and the session admin is unaffected.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile

# Meme source que `main.SITE_URL`, lue ici directement : main importe ce
# module, l'importer en retour ferait un cycle a l'initialisation.
SITE_URL = os.environ.get("BILLETS_SITE_URL", "")
from pydantic import BaseModel, ValidationError

from .. import repo
from ..ids import new_ulid
from ..models import BilletIn
from ..services import feeds, media

try:
    from secubox_core.auth import require_jwt
except Exception:  # pragma: no cover - secubox_core absent in isolated tests
    require_jwt = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BilletPayload(BaseModel):
    body: str
    ref_url: Optional[str] = None
    embed_url: Optional[str] = None
    style: str = "default"
    status: str = "published"  # "published" | "draft"


def _permalien(slug: Optional[str]) -> str:
    """L'adresse publique du billet (#1024).

    POURQUOI ELLE MANQUAIT. Cette surface rendait `id` et `slug`, jamais
    l'adresse. Le BBS, qui publie par ici, lisait un champ `url` qui n'a jamais
    existe : il enregistrait donc une adresse vide pour chaque billet. Rien
    n'echouait — la publication reussissait, le billet etait en ligne — et la
    page Billets du BBS renvoyait vers le fil en annoncant « adresse
    manquante ». Un defaut d'ABSENCE ne se signale pas tout seul.

    L'adresse est calculee depuis `BILLETS_SITE_URL`, deja renseigne : billets
    CONNAISSAIT son adresse publique, il ne la disait pas a qui la demandait.

    Sans base configuree on rend un chemin relatif plutot qu'une adresse
    inventee : `/b/slug` est vrai pour qui parle deja a billets, alors qu'un
    `http://localhost/...` fabrique serait un lien mort presente comme bon.
    """
    if not slug:
        return ""
    base = (SITE_URL or "").rstrip("/")
    return f"{base}/b/{slug}" if base else f"/b/{slug}"


def _view(row, tags: Optional[list] = None) -> dict:
    d = dict(row)
    return {
        "id": d.get("id"),
        "slug": d.get("slug"),
        # `permalink` ET `url` : le premier est le nom employe par le rendu
        # public, le second celui qu'attendent les clients existants. Servir
        # les deux coute un champ et evite de casser l'un pour reparer l'autre.
        "permalink": _permalien(d.get("slug")),
        "url": _permalien(d.get("slug")),
        "body": d.get("body"),
        # A short excerpt so list views can show a few words instead of the whole
        # billet; `body` stays available for the editor.
        "summary": feeds.excerpt(d.get("body") or "", max_len=140),
        "status": d.get("status"),
        "style": d.get("style"),
        "ref_url": d.get("ref_url"),
        "embed_url": d.get("embed_url"),
        "published_at": d.get("published_at"),
        "created_at": d.get("created_at"),
        "tags": tags or [],
    }


def register_jwt_admin(app: FastAPI) -> None:
    """Register the /admin/api/* JSON surface. No-op if secubox_core is absent."""
    if require_jwt is None:
        return

    def _billet_in(p: BilletPayload) -> BilletIn:
        try:
            return BilletIn(body=p.body, ref_url=p.ref_url, embed_url=p.embed_url,
                            style=p.style, publish=(p.status == "published"))
        except ValidationError as exc:
            raise HTTPException(422, f"invalid billet: {exc.errors()}")

    @app.get("/admin/api/billets")
    async def api_list(request: Request, status: Optional[str] = None,
                       tag: Optional[str] = None, limit: int = 100,
                       user=Depends(require_jwt)):
        """Authoring list — REAL billet ids, and drafts included.

        The public JSON Feed cannot serve this: its item `id` is a permalink URL
        (not the billet id, so edit/delete could not address a row) and it omits
        drafts entirely, which an authoring client must see.
        """
        conn = request.app.state.conn
        rows = await repo.list_all(conn, status=status, limit=max(1, min(limit, 200)))
        tag_map = await repo.tags_for_many(conn, [r["id"] for r in rows])   # batched, no N+1
        out = [_view(r, tag_map.get(r["id"], [])) for r in rows]
        if tag:
            out = [b for b in out if any(t["slug"] == tag for t in b["tags"])]
        return {"billets": out, "count": len(out)}

    @app.get("/admin/api/tags")
    async def api_tags(request: Request, user=Depends(require_jwt)):
        """Emoji hashtags in use (published), most-used first — the chip bar."""
        return {"tags": await repo.list_tags(request.app.state.conn)}

    @app.post("/admin/api/billets")
    async def api_create(request: Request, payload: BilletPayload, user=Depends(require_jwt)):
        data = _billet_in(payload)
        conn = request.app.state.conn
        billet_id = await repo.create_billet(conn, data, now=_now())
        row = await repo.get_by_id(conn, billet_id)
        return {"success": True, **_view(row)}

    @app.put("/admin/api/billets/{billet_id}")
    async def api_update(request: Request, billet_id: str, payload: BilletPayload,
                         user=Depends(require_jwt)):
        conn = request.app.state.conn
        if await repo.get_by_id(conn, billet_id) is None:
            raise HTTPException(404, "billet not found")
        data = _billet_in(payload)
        await repo.update_billet(conn, billet_id, body=data.body, ref_url=data.ref_url,
                                 embed_url=data.embed_url, now=_now())
        await repo.set_status(conn, billet_id,
                              "published" if data.publish else "draft", now=_now())
        return {"success": True, **_view(await repo.get_by_id(conn, billet_id))}

    @app.delete("/admin/api/billets/{billet_id}")
    async def api_delete(request: Request, billet_id: str, user=Depends(require_jwt)):
        conn = request.app.state.conn
        if await repo.get_by_id(conn, billet_id) is None:
            raise HTTPException(404, "billet not found")
        await repo.delete_billet(conn, billet_id)
        return {"success": True, "id": billet_id, "deleted": True}

    @app.post("/admin/api/billets/{billet_id}/media")
    async def api_media(request: Request, billet_id: str, file: UploadFile = File(...),
                        user=Depends(require_jwt)):
        conn = request.app.state.conn
        if await repo.get_by_id(conn, billet_id) is None:
            raise HTTPException(404, "billet not found")
        raw = await file.read()
        if not raw:
            raise HTTPException(400, "empty file")
        try:
            processed = await asyncio.to_thread(media.process, raw)
        except media.MediaError as exc:
            raise HTTPException(415, f"unsupported media: {exc}")
        mid = new_ulid()
        fn, thumb = await asyncio.to_thread(media.store, mid, processed)
        await repo.add_media(conn, billet_id, filename=fn, thumb=thumb,
                             mime=processed["mime"], width=processed["width"],
                             height=processed["height"], alt="", now=_now(), ulid=mid)
        return {"success": True, "id": mid, "url": f"/media/{fn}", "thumb": f"/media/{thumb}"}

    @app.get("/admin/api/comments")
    async def api_comments(request: Request, status: str = "pending",
                           user=Depends(require_jwt)):
        rows = await repo.list_pending_comments(request.app.state.conn)
        return {"comments": [dict(r) for r in rows]}

    @app.post("/admin/api/comments/{comment_id}/approve")
    async def api_comment_approve(request: Request, comment_id: str,
                                  user=Depends(require_jwt)):
        conn = request.app.state.conn
        if await repo.get_comment(conn, comment_id) is None:
            raise HTTPException(404, "comment not found")
        await repo.moderate_comment(conn, comment_id, "approved")
        return {"success": True, "id": comment_id, "status": "approved"}

    @app.delete("/admin/api/comments/{comment_id}")
    async def api_comment_delete(request: Request, comment_id: str,
                                 user=Depends(require_jwt)):
        conn = request.app.state.conn
        if await repo.get_comment(conn, comment_id) is None:
            raise HTTPException(404, "comment not found")
        await repo.moderate_comment(conn, comment_id, "rejected")
        return {"success": True, "id": comment_id, "status": "rejected"}
