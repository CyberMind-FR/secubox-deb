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
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, ValidationError

from .. import repo
from ..ids import new_ulid
from ..models import BilletIn
from ..services import media

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


def _view(row) -> dict:
    d = dict(row)
    return {
        "id": d.get("id"),
        "slug": d.get("slug"),
        "body": d.get("body"),
        "status": d.get("status"),
        "style": d.get("style"),
        "ref_url": d.get("ref_url"),
        "embed_url": d.get("embed_url"),
        "published_at": d.get("published_at"),
        "created_at": d.get("created_at"),
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
