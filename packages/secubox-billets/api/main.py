# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""FastAPI app factory for billets.

`create_app(conn)` wires the public read surface over an already-open aiosqlite
connection (tests pass a fixture conn; the runtime opens one in a lifespan).
The public feed is server-rendered Jinja2 with keyset pagination."""
from __future__ import annotations

import os
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import repo
from .routes.admin import register_admin
from .services import security as sec
from .services.render import render_markdown

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"
DEFAULT_REVISIONS_DIR = os.environ.get(
    "BILLETS_REVISIONS_DIR", "/var/lib/secubox/billets/revisions")

SITE_TITLE = "billets"
SITE_TAGLINE = "micro-blog gateway"
PAGE_SIZE = 20

# frame-src is limited to the embed provider allowlist (spec). Registrable
# domains → "https://d https://*.d" so provider embed subdomains match.
_FRAME_HOSTS = [
    "youtube.com", "youtube-nocookie.com", "vimeo.com", "twitter.com",
    "bsky.app", "soundcloud.com", "bandcamp.com", "flickr.com",
]


def _frame_src(extra_hosts: tuple[str, ...] = ()) -> str:
    parts = []
    for d in list(_FRAME_HOSTS) + [h for h in extra_hosts if h]:
        parts.append(f"https://{d}")
        parts.append(f"https://*.{d}")
    return " ".join(parts)


def _csp(frame_src: str) -> str:
    return (
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self'; script-src 'self'; base-uri 'none'; "
        f"form-action 'self'; frame-ancestors 'none'; frame-src {frame_src}"
    )


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": _csp(_frame_src()),
}


def _billet_view(row: aiosqlite.Row) -> dict:
    d = dict(row)
    d["body_html"] = render_markdown(d["body"])
    return d


def create_app(conn: aiosqlite.Connection, *, secret: str | None = None,
               revisions_dir: str | None = None) -> FastAPI:
    app = FastAPI(title="billets", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.conn = conn
    app.state.secret = secret or sec.get_secret()
    app.state.revisions_dir = revisions_dir or DEFAULT_REVISIONS_DIR
    # Outbound HTTP for oEmbed/OpenGraph (SSRF-guarded in services.ssrf). Tests
    # override app.state.http_client with a MockTransport client + resolver.
    import httpx as _httpx
    app.state.http_client = _httpx.AsyncClient(headers={"user-agent": "billets/0.1 (+secubox)"})
    from .services import ssrf as _ssrf
    app.state.resolver = _ssrf._default_resolver
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    register_admin(app, templates)

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
        resp = templates.TemplateResponse(request, "billet.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billet": _billet_view(row),
        })
        # A self-hosted embed (Mastodon/PeerTube) needs its instance host in
        # frame-src; add it for this page only.
        if row["embed_html"] and row["embed_url"]:
            from urllib.parse import urlparse
            host = urlparse(row["embed_url"]).hostname
            if host and not any(host == d or host.endswith("." + d) for d in _FRAME_HOSTS):
                resp.headers["Content-Security-Policy"] = _csp(_frame_src((host,)))
        return resp

    return app
