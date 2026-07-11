# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Admin surface: session login (argon2id + optional TOTP, rate-limited, CSRF)
and billet CRUD. Every mutation appends to the hash-chained event_log and
commits a Gitea revision (content + style) off the event loop."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from .. import repo
from ..models import BilletIn
from ..services import eventlog, linkcard, revisions
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

    @app.post("/admin/billets")
    async def create(request: Request, body: str = Form(...), url: str = Form(""),
                     url_kind: str = Form("ref"), action: str = Form("draft"),
                     csrf: str = Form("")):
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
        token = _csrf_token(request)
        resp = templates.TemplateResponse(request, "admin_edit.html",
                                          {"billet": dict(row), "error": None, "csrf": token})
        _set_csrf(resp, request, token)
        return resp

    @app.post("/admin/billets/{billet_id}")
    async def update(request: Request, billet_id: str, body: str = Form(...),
                     url: str = Form(""), url_kind: str = Form("ref"),
                     action: str = Form("save"), csrf: str = Form("")):
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
            await eventlog.append_event(conn, "billet.deleted",
                                        {"id": billet_id, "slug": row["slug"],
                                         "by": author["username"]}, ts=_now(request))
            await repo.delete_billet(conn, billet_id)
        return _redirect("/admin")
