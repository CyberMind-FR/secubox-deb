# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""FastAPI app factory for billets.

`create_app(conn)` wires the public read surface over an already-open aiosqlite
connection (tests pass a fixture conn; the runtime opens one in a lifespan).
The public feed is server-rendered Jinja2 with keyset pagination."""
from __future__ import annotations

import os
import time
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import repo
from .routes.admin import register_admin
from .routes.public import (PCSRF_COOKIE, VISITOR_COOKIE, reactions_context,
                            register_public, _visitor)
from .services import antispam, feeds, media
from .services import security as sec
from .services.render import linkify_plain, render_markdown

SITE_URL = os.environ.get("BILLETS_SITE_URL", "")


def _base(request: Request) -> str:
    if SITE_URL:
        return SITE_URL.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{proto}://{host}"


def _share_intents(url: str, title: str) -> dict:
    from urllib.parse import quote_plus
    u, t = quote_plus(url), quote_plus(title)
    ut = quote_plus(f"{title} {url}")
    return {
        "bluesky": f"https://bsky.app/intent/compose?text={ut}",
        "x": f"https://twitter.com/intent/tweet?url={u}&text={t}",
        "facebook": f"https://www.facebook.com/sharer/sharer.php?u={u}",
        "linkedin": f"https://www.linkedin.com/sharing/share-offsite/?url={u}",
        "whatsapp": f"https://wa.me/?text={ut}",
        "telegram": f"https://t.me/share/url?url={u}&text={t}",
        "reddit": f"https://www.reddit.com/submit?url={u}&title={t}",
        "email": f"mailto:?subject={t}&body={u}",
    }

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


def _extra_frame_hosts(rows) -> tuple[str, ...]:
    """Self-hosted embed hosts (Mastodon/PeerTube) among the given billet rows,
    to add to frame-src beyond the static provider allowlist."""
    from urllib.parse import urlparse
    hosts: list[str] = []
    for r in rows:
        if r["embed_html"] and r["embed_url"]:
            h = urlparse(r["embed_url"]).hostname
            if h and h not in hosts and not any(h == d or h.endswith("." + d) for d in _FRAME_HOSTS):
                hosts.append(h)
    return tuple(hosts)


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": _csp(_frame_src()),
}


def _billet_view(row: aiosqlite.Row, base: str = "", media_rows=None) -> dict:
    from urllib.parse import urlparse
    d = dict(row)
    d["body_html"] = render_markdown(d["body"])
    d["ref_host"] = (urlparse(d["ref_url"]).hostname if d.get("ref_url") else None)
    title = feeds.billet_title(d["body"])
    d["title"] = title
    d["permalink"] = f"{base}/b/{d['slug']}" if base else f"/b/{d['slug']}"
    d["share"] = _share_intents(d["permalink"], title) if base else {}
    d["media"] = [dict(m) for m in (media_rows or [])]
    return d


def create_app(conn: aiosqlite.Connection | None = None, *, secret: str | None = None,
               revisions_dir: str | None = None, lifespan=None) -> FastAPI:
    # `conn` may be None when a `lifespan` opens the DB at startup (runtime);
    # tests pass a live connection and no lifespan. Routes read
    # `app.state.conn` at request time, so either wiring works.
    app = FastAPI(title="billets", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
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
    # User-uploaded media (re-encoded, EXIF-stripped in services.media). In prod
    # nginx serves /media/ directly; this mount is the in-process fallback.
    try:
        media_root = media.media_dir()
        media_root.mkdir(parents=True, exist_ok=True)
        app.mount("/media", StaticFiles(directory=str(media_root)), name="media")
    except OSError:
        pass
    register_admin(app, templates)
    register_public(app, templates)

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
        base = _base(request)
        media_map = await repo.list_media_for(app.state.conn, [r["id"] for r in rows])
        resp = templates.TemplateResponse(request, "feed.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billets": [_billet_view(r, base, media_map.get(r["id"])) for r in rows],
            "next_cursor": next_cursor,
        })
        # Embeds render inline in the feed too; allow any self-hosted embed hosts
        # of the shown billets in frame-src (static providers already covered).
        resp.headers["Content-Security-Policy"] = _csp(_frame_src(_extra_frame_hosts(rows)))
        return resp

    @app.get("/b/{slug}", response_class=HTMLResponse)
    async def permalink(request: Request, slug: str):
        row = await repo.get_by_slug(app.state.conn, slug)
        if row is None or row["status"] != "published":
            raise HTTPException(status_code=404, detail="Billet introuvable")
        await repo.increment_view(app.state.conn, row["id"])
        vhash, new_vtoken = _visitor(request)
        pcsrf = request.cookies.get(PCSRF_COOKIE) or sec.new_csrf_token()
        ts_token = antispam.issue_form_token(app.state.secret, now_epoch=int(time.time()))
        rctx = await reactions_context(request, row["id"], vhash, slug=row["slug"])
        rctx["pcsrf"] = pcsrf
        comments = await repo.list_approved_comments(app.state.conn, row["id"])
        comment_views = [{**dict(c), "body_html": linkify_plain(c["body"])} for c in comments]
        base = _base(request)
        permalink_url = f"{base}/b/{row['slug']}"
        media_rows = await repo.list_media(app.state.conn, row["id"])
        resp = templates.TemplateResponse(request, "billet.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billet": _billet_view(row, base, media_rows), "reactions": rctx,
            "comments": comment_views, "pcsrf": pcsrf,
            "ts_token": ts_token, "flash": request.query_params.get("c"),
            "og": {"title": feeds.billet_title(row["body"]),
                   "desc": feeds.excerpt(row["body"]), "url": permalink_url,
                   "image": (f"{base}/media/{media_rows[0]['filename']}" if media_rows else None)},
            "oembed_url": f"{base}/oembed?url={permalink_url}&format=json",
            "share": _share_intents(permalink_url, feeds.billet_title(row["body"])),
        })
        resp.set_cookie(PCSRF_COOKIE, pcsrf, httponly=True, samesite="lax",
                        secure=(request.headers.get("x-forwarded-proto", request.url.scheme) == "https"),
                        path="/")
        if new_vtoken:
            resp.set_cookie(VISITOR_COOKIE, new_vtoken, httponly=True, samesite="lax",
                            secure=(request.headers.get("x-forwarded-proto", request.url.scheme) == "https"),
                            max_age=31536000, path="/")
        # A self-hosted embed (Mastodon/PeerTube) needs its instance host in
        # frame-src; add it for this page only.
        if row["embed_html"] and row["embed_url"]:
            from urllib.parse import urlparse
            host = urlparse(row["embed_url"]).hostname
            if host and not any(host == d or host.endswith("." + d) for d in _FRAME_HOSTS):
                resp.headers["Content-Security-Policy"] = _csp(_frame_src((host,)))
        return resp

    async def _feed_rows() -> list[aiosqlite.Row]:
        rows, _ = await repo.list_published(app.state.conn, limit=30)
        return rows

    @app.get("/feed.xml")
    async def feed_atom(request: Request):
        from fastapi.responses import Response
        base = _base(request)
        rows = await _feed_rows()
        entries = [{
            "title": feeds.billet_title(r["body"]),
            "url": f"{base}/b/{r['slug']}", "id": f"{base}/b/{r['slug']}",
            "updated": r["updated_at"], "published": r["published_at"] or r["updated_at"],
            "content_html": render_markdown(r["body"]),
        } for r in rows]
        updated = rows[0]["updated_at"] if rows else "1970-01-01T00:00:00Z"
        xml = feeds.build_atom(site_title=SITE_TITLE, base_url=base,
                               self_url=f"{base}/feed.xml", entries=entries, updated=updated)
        return Response(xml, media_type="application/atom+xml")

    @app.get("/feed.json")
    async def feed_json(request: Request):
        base = _base(request)
        rows = await _feed_rows()
        items = [{
            "id": f"{base}/b/{r['slug']}", "url": f"{base}/b/{r['slug']}",
            "title": feeds.billet_title(r["body"]),
            "content_html": render_markdown(r["body"]),
            "date_published": r["published_at"] or r["updated_at"],
        } for r in rows]
        return feeds.build_jsonfeed(site_title=SITE_TITLE, base_url=base,
                                    feed_url=f"{base}/feed.json", items=items)

    @app.get("/stats.json")
    async def stats_json(request: Request):
        # Public aggregate counts for the SecuBox admin panel (cross-origin).
        from fastapi.responses import JSONResponse
        base = _base(request)
        s = await repo.stats(app.state.conn)
        rows, _ = await repo.list_published(app.state.conn, limit=6)
        s["latest"] = [{"title": feeds.billet_title(r["body"]),
                        "url": f"{base}/b/{r['slug']}",
                        "date": (r["published_at"] or r["updated_at"])[:10]} for r in rows]
        s["site_url"] = f"{base}/"
        return JSONResponse(s, headers={"Access-Control-Allow-Origin": "*",
                                        "Cache-Control": "public, max-age=30"})

    @app.get("/oembed")
    async def oembed_out(request: Request, url: str, format: str = "json",
                         maxwidth: int | None = None, maxheight: int | None = None):
        # Outbound oEmbed so billets embed elsewhere. Only OUR own permalinks.
        from urllib.parse import urlparse
        from fastapi import HTTPException as _HE
        p = urlparse(url)
        parts = [seg for seg in p.path.split("/") if seg]
        if len(parts) != 2 or parts[0] != "b":
            raise _HE(status_code=404, detail="not an oembeddable billet URL")
        row = await repo.get_by_slug(app.state.conn, parts[1])
        if row is None or row["status"] != "published":
            raise _HE(status_code=404, detail="billet not found")
        base = _base(request)
        title = feeds.billet_title(row["body"])
        from html import escape as _esc
        permalink = f"{base}/b/{row['slug']}"
        html = (f'<blockquote class="billet-embed" lang="fr">'
                f'<p>{_esc(feeds.excerpt(row["body"]))}</p>'
                f'<cite>— <a href="{_esc(permalink)}">{_esc(SITE_TITLE)}</a></cite>'
                f'</blockquote>')
        return {
            "type": "rich", "version": "1.0", "provider_name": SITE_TITLE,
            "provider_url": f"{base}/", "title": title,
            "html": html, "width": maxwidth or 480, "height": maxheight or 180,
        }

    return app
