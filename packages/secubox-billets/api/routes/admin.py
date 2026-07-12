# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Admin surface: session login (argon2id + optional TOTP, rate-limited, CSRF)
and billet CRUD. Every mutation appends to the hash-chained event_log and
commits a Gitea revision (content + style) off the event loop."""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from .. import repo
from ..ids import new_ulid
from ..models import BilletIn
from ..services import eventlog, linkcard, media, revisions
from ..services import security as sec
from ..services import ssrf as ssrf_mod

SESSION_COOKIE = "billets_session"
CSRF_COOKIE = "billets_csrf"


def _now(request: Request) -> str:
    # Timestamp source is injectable for tests via app.state.clock.
    clock = getattr(request.app.state, "clock", None)
    if clock is not None:
        return clock()
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _client_ip(request: Request) -> str:
    # Honour X-Forwarded-For (set by the nginx→sbxwaf→HAProxy chain) so the
    # login rate-limit keys on the real client, not the shared proxy IP.
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _csrf_token(request: Request) -> str:
    """Reuse the existing double-submit token if present, else mint one."""
    return request.cookies.get(CSRF_COOKIE) or sec.new_csrf_token()


def _set_csrf(response, request: Request, token: str) -> None:
    response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="lax",
                        secure=_secure(request), path="/admin")


def _secure(request: Request) -> bool:
    # Behind nginx TLS; honour X-Forwarded-Proto, default secure unless plain test.
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


async def _current_author(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    author_id = sec.read_session(request.app.state.secret, token)
    if not author_id:
        return None
    return await repo.get_author_by_id(request.app.state.conn, author_id)


async def _log_and_revision(request: Request, event_type: str, billet_row, *, actor: str):
    """Append the chained event-log row, then commit a Gitea revision off-loop."""
    payload = {"id": billet_row["id"], "slug": billet_row["slug"], "by": actor}
    await eventlog.append_event(request.app.state.conn, event_type, payload, ts=_now(request))
    repo_dir = Path(request.app.state.revisions_dir)
    meta = {
        "slug": billet_row["slug"], "status": billet_row["status"],
        "created_at": billet_row["created_at"], "updated_at": billet_row["updated_at"],
        "published_at": billet_row["published_at"], "ref_url": billet_row["ref_url"],
        "embed_url": billet_row["embed_url"], "embed_provider": billet_row["embed_provider"],
        "style": "default",
    }
    msg = f"{event_type} {billet_row['slug']} by {actor}"
    await asyncio.to_thread(revisions.commit_revision, repo_dir, billet_row["id"],
                            billet_row["body"], meta, msg)


async def _resolve_and_store_embed(request: Request, billet_id: str, embed_url: str | None):
    """Resolve an embed_url (oEmbed → link-card, SSRF-guarded, sanitized) and
    cache the HTML on the row. Never raises — embedding must not break a save."""
    if not embed_url:
        return
    client = request.app.state.http_client
    resolver = getattr(request.app.state, "resolver", ssrf_mod._default_resolver)
    res = await linkcard.resolve_embed(embed_url, client=client, resolver=resolver)
    await repo.set_embed(request.app.state.conn, billet_id, html=res["html"],
                         provider=res["provider"], fetched_at=_now(request))


def register_admin(app: FastAPI, templates: Jinja2Templates) -> None:
    login_limiter = sec.RateLimiter(max_events=5, window_s=3600)
    app.state.login_limiter = login_limiter

    def _redirect(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=303)

    @app.get("/admin/login", response_class=HTMLResponse)
    async def login_form(request: Request, error: str | None = None):
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_login.html",
                                          {"error": error, "csrf": token})
        _set_csrf(resp, request, token)
        return resp

    @app.post("/admin/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...),
                    totp: str = Form(""), csrf: str = Form("")):
        conn = request.app.state.conn
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        ip_hash = sec.hash_ip(_client_ip(request), request.app.state.secret)
        if not login_limiter.check_and_add(ip_hash):
            return _redirect("/admin/login?error=ratelimit")
        author = await repo.get_author_by_username(conn, username)
        ok = False
        if author is not None:
            ok = await asyncio.to_thread(sec.verify_password, author["password_hash"], password)
            ok = ok and sec.verify_totp(author["totp_secret"], totp)
        if not ok:
            await eventlog.append_event(conn, "author.login_failed",
                                        {"username": username[:40]}, ts=_now(request))
            return _redirect("/admin/login?error=bad")
        await eventlog.append_event(conn, "author.login", {"id": author["id"]}, ts=_now(request))
        resp = _redirect("/admin")
        resp.set_cookie(SESSION_COOKIE, sec.issue_session(request.app.state.secret, author["id"]),
                        httponly=True, samesite="lax", secure=_secure(request),
                        max_age=sec.SESSION_MAX_AGE, path="/")
        return resp

    @app.post("/admin/logout")
    async def logout(request: Request, csrf: str = Form("")):
        resp = _redirect("/admin/login")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/admin", response_class=HTMLResponse)
    async def dashboard(request: Request, status: str | None = None):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        billets = await repo.list_all(request.app.state.conn, status=status)
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_dash.html", {
            "billets": [dict(b) for b in billets], "status": status,
            "author": dict(author), "csrf": token})
        _set_csrf(resp, request, token)
        return resp

    @app.get("/admin/billets/new", response_class=HTMLResponse)
    async def new_form(request: Request):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_edit.html",
                                          {"billet": None, "error": None, "csrf": token})
        _set_csrf(resp, request, token)
        return resp

    def _urls(url: str, url_kind: str) -> tuple[str | None, str | None]:
        url = (url or "").strip()
        if not url:
            return None, None
        return (None, url) if url_kind == "embed" else (url, None)

    async def _save_uploads(request: Request, billet_id: str,
                            files: list[UploadFile]) -> int:
        """Process + store each valid uploaded image as a media attachment.
        Invalid/oversized files are skipped (non-fatal); returns the count of
        files that were rejected so the caller can flash a warning."""
        conn = request.app.state.conn
        skipped = 0
        for up in files or []:
            if up is None or not (up.filename or "").strip():
                continue
            raw = await up.read()
            if not raw:
                continue
            try:
                processed = await asyncio.to_thread(media.process, raw)
            except media.MediaError:
                skipped += 1
                continue
            mid = new_ulid()
            fn, thumb = await asyncio.to_thread(media.store, mid, processed)
            await repo.add_media(conn, billet_id, filename=fn, thumb=thumb,
                                 mime=processed["mime"], width=processed["width"],
                                 height=processed["height"], alt="",
                                 now=_now(request), ulid=mid)
        return skipped

    @app.post("/admin/billets")
    async def create(request: Request, body: str = Form(...), url: str = Form(""),
                     url_kind: str = Form("ref"), action: str = Form("draft"),
                     csrf: str = Form(""), media_files: list[UploadFile] = File(default=[])):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        ref_url, embed_url = _urls(url, url_kind)
        try:
            data = BilletIn(body=body, ref_url=ref_url, embed_url=embed_url,
                            publish=(action == "publish"))
        except ValidationError:
            resp = templates.TemplateResponse(request, "admin_edit.html",
                {"billet": None, "error": "Entrée invalide (corps ou URL https).",
                 "csrf": request.cookies.get(CSRF_COOKIE) or ""})
            return resp
        billet_id = await repo.create_billet(request.app.state.conn, data, now=_now(request))
        await _save_uploads(request, billet_id, media_files)
        await _resolve_and_store_embed(request, billet_id, data.embed_url)
        row = await repo.get_by_id(request.app.state.conn, billet_id)
        event = "billet.published" if data.publish else "billet.edited"
        await _log_and_revision(request, event, row, actor=author["username"])
        return _redirect("/admin")

    @app.get("/admin/billets/{billet_id}/edit", response_class=HTMLResponse)
    async def edit_form(request: Request, billet_id: str):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        row = await repo.get_by_id(request.app.state.conn, billet_id)
        if row is None:
            return _redirect("/admin")
        media_rows = await repo.list_media(request.app.state.conn, billet_id)
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_edit.html",
                                          {"billet": dict(row), "error": None, "csrf": token,
                                           "media": [dict(m) for m in media_rows]})
        _set_csrf(resp, request, token)
        return resp

    @app.post("/admin/billets/{billet_id}")
    async def update(request: Request, billet_id: str, body: str = Form(...),
                     url: str = Form(""), url_kind: str = Form("ref"),
                     action: str = Form("save"), csrf: str = Form(""),
                     media_files: list[UploadFile] = File(default=[])):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        conn = request.app.state.conn
        row = await repo.get_by_id(conn, billet_id)
        if row is None:
            return _redirect("/admin")
        ref_url, embed_url = _urls(url, url_kind)
        try:
            BilletIn(body=body, ref_url=ref_url, embed_url=embed_url)
        except ValidationError:
            resp = templates.TemplateResponse(request, "admin_edit.html",
                {"billet": dict(row), "error": "Entrée invalide.",
                 "csrf": request.cookies.get(CSRF_COOKIE) or ""})
            return resp
        await repo.update_billet(conn, billet_id, body=body, ref_url=ref_url,
                                 embed_url=embed_url, now=_now(request))
        await _save_uploads(request, billet_id, media_files)
        if action in ("publish", "archive"):
            await repo.set_status(conn, billet_id,
                                  "published" if action == "publish" else "archived",
                                  now=_now(request))
        await _resolve_and_store_embed(request, billet_id, embed_url)
        row = await repo.get_by_id(conn, billet_id)
        event = "billet.published" if action == "publish" else "billet.edited"
        await _log_and_revision(request, event, row, actor=author["username"])
        return _redirect("/admin")

    @app.post("/admin/billets/{billet_id}/refetch")
    async def refetch(request: Request, billet_id: str, csrf: str = Form("")):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        row = await repo.get_by_id(request.app.state.conn, billet_id)
        if row is not None and row["embed_url"]:
            await _resolve_and_store_embed(request, billet_id, row["embed_url"])
        return _redirect(f"/admin/billets/{billet_id}/edit")

    @app.post("/admin/billets/{billet_id}/delete")
    async def delete(request: Request, billet_id: str, csrf: str = Form("")):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        conn = request.app.state.conn
        row = await repo.get_by_id(conn, billet_id)
        if row is not None:
            for m in await repo.list_media(conn, billet_id):
                await asyncio.to_thread(media.delete_files, m["filename"], m["thumb"])
            await eventlog.append_event(conn, "billet.deleted",
                                        {"id": billet_id, "slug": row["slug"],
                                         "by": author["username"]}, ts=_now(request))
            await repo.delete_billet(conn, billet_id)   # media rows cascade
        return _redirect("/admin")

    @app.post("/admin/media/{media_id}/delete")
    async def delete_media_route(request: Request, media_id: str, csrf: str = Form("")):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        conn = request.app.state.conn
        row = await repo.get_media(conn, media_id)
        if row is None:
            return _redirect("/admin")
        billet_id = row["billet_id"]
        await asyncio.to_thread(media.delete_files, row["filename"], row["thumb"])
        await repo.delete_media(conn, media_id)
        return _redirect(f"/admin/billets/{billet_id}/edit")

    @app.get("/admin/export.sbxsite")
    async def export_site(request: Request):
        """Portable single-file backup: every billet + its media inlined as
        base64. Re-importable elsewhere; the media travels with the file."""
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        conn = request.app.state.conn
        billets = [dict(r) for r in await repo.list_all(conn)]
        media_out = []
        for m in await repo.all_media(conn):
            md = dict(m)
            try:
                raw = await asyncio.to_thread(media.read_bytes, m["filename"])
                md["b64"] = base64.b64encode(raw).decode("ascii")
            except OSError:
                md["b64"] = None
            media_out.append(md)
        payload = {"format": "sbxsite/billets", "version": 1,
                   "exported_at": _now(request), "billets": billets, "media": media_out}
        resp = JSONResponse(payload)
        resp.headers["Content-Disposition"] = 'attachment; filename="billets.sbxsite"'
        return resp

    @app.get("/admin/comments", response_class=HTMLResponse)
    async def comments_queue(request: Request):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        pending = await repo.list_pending_comments(request.app.state.conn)
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_comments.html",
                                          {"pending": [dict(c) for c in pending], "csrf": token})
        _set_csrf(resp, request, token)
        return resp

    @app.post("/admin/comments/{comment_id}/moderate")
    async def moderate(request: Request, comment_id: str, decision: str = Form(...),
                       csrf: str = Form("")):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        conn = request.app.state.conn
        row = await repo.get_comment(conn, comment_id)
        if row is not None and decision in ("approve", "reject"):
            status = "approved" if decision == "approve" else "rejected"
            await repo.moderate_comment(conn, comment_id, status)
            await eventlog.append_event(
                conn, "comment.approved" if decision == "approve" else "comment.rejected",
                {"id": comment_id, "by": author["username"]}, ts=_now(request))
        return _redirect("/admin/comments")

    @app.post("/admin/password")
    async def change_password(request: Request, current: str = Form(...),
                              new_password: str = Form(...), confirm: str = Form(""),
                              csrf: str = Form("")):
        author = await _current_author(request)
        if author is None:
            return _redirect("/admin/login")
        if not sec.csrf_ok(request.cookies.get(CSRF_COOKIE), csrf):
            return _redirect("/admin/login?error=csrf")
        if len(new_password) < 10 or new_password != confirm:
            return _redirect("/admin?pw=invalid")
        ok = await asyncio.to_thread(sec.verify_password, author["password_hash"], current)
        if not ok:
            return _redirect("/admin?pw=bad")
        new_hash = await asyncio.to_thread(sec.hash_password, new_password)
        await repo.update_password(request.app.state.conn, author["id"], new_hash)
        await eventlog.append_event(request.app.state.conn, "author.password_changed",
                                    {"id": author["id"]}, ts=_now(request))
        # Force re-login with the new password (this device); other sessions
        # expire at the 12h cap.
        resp = _redirect("/admin/login?pw=changed")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp
