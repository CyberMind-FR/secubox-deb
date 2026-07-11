# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""FastAPI app factory for billets.

`create_app(conn)` wires the public read surface over an already-open aiosqlite
connection (tests pass a fixture conn; the runtime opens one in a lifespan).
The public feed is server-rendered Jinja2 with keyset pagination."""
from __future__ import annotations

from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import repo
from .services.render import render_markdown

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"

SITE_TITLE = "billets"
SITE_TAGLINE = "micro-blog gateway"
PAGE_SIZE = 20

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    # No inline scripts anywhere; htmx is served from /static.
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self'; script-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


def _billet_view(row: aiosqlite.Row) -> dict:
    d = dict(row)
    d["body_html"] = render_markdown(d["body"])
    return d


def create_app(conn: aiosqlite.Connection) -> FastAPI:
    app = FastAPI(title="billets", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.conn = conn
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "module": "billets"}

    @app.get("/", response_class=HTMLResponse)
    async def feed(request: Request, cursor: str | None = None):
        rows, next_cursor = await repo.list_published(app.state.conn, limit=PAGE_SIZE, cursor=cursor)
        return templates.TemplateResponse(request, "feed.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billets": [_billet_view(r) for r in rows], "next_cursor": next_cursor,
        })

    @app.get("/b/{slug}", response_class=HTMLResponse)
    async def permalink(request: Request, slug: str):
        row = await repo.get_by_slug(app.state.conn, slug)
        if row is None or row["status"] != "published":
            raise HTTPException(status_code=404, detail="Billet introuvable")
        await repo.increment_view(app.state.conn, row["id"])
        return templates.TemplateResponse(request, "billet.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billet": _billet_view(row),
        })

    return app
